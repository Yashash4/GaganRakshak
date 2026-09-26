import ast
from pathlib import Path

import numpy as np
from pymavlink.dialects.v20 import ardupilotmega as mav2

from gaganrakshak import estimator
from gaganrakshak.estimator import EstimatorMonitor, learn, onsets
from gaganrakshak.evidence import Severity

AP = mav2.MAVLink(None, srcSystem=1, srcComponent=1)
CALIB = {
    "thresholds": {"pos_horiz_variance": 0.5, "compass_variance": 0.4, "terrain_alt_variance": None},
    "persist_s": 2.0,
}


def ekf(pos=0.2, compass=0.1, src=AP):
    m = mav2.MAVLink_ekf_status_report_message(0x033F, 0.1, pos, 0.05, compass, 0.0)
    m.pack(src)  # sets the header (source system)
    return m


def feed(det, values, dt=0.02, **kw):
    return [e for i, v in enumerate(values) for e in det.observe(ekf(pos=v, **kw), [], "D", i * dt)]


def test_steady_clean_level_gives_no_evidence():
    assert feed(EstimatorMonitor(CALIB), [0.3] * 1000) == []


def test_step_held_for_persist_gives_one_advisory():
    ev = feed(EstimatorMonitor(CALIB), [0.3] * 100 + [0.9] * 200)  # 4 s above threshold
    assert len(ev) == 1
    e = ev[0]
    assert e.evidence_type == "estimator_innovation_high" and e.severity == Severity.LOW
    assert e.class_hint == "gnss_integrity_advisory" and e.metadata["ratio"] == "pos_horiz_variance"
    assert abs(e.t - (2.0 + 2.0)) < 0.021 and e.metadata["flags"] == 0x033F


def test_one_sample_spike_and_short_excursions_give_none():
    assert feed(EstimatorMonitor(CALIB), [0.3] * 100 + [5.0] + [0.3] * 100) == []
    assert feed(EstimatorMonitor(CALIB), ([0.3] * 10 + [0.9] * 90) * 5) == []  # 1.8 s each time


def test_compass_ratio_is_its_own_class_and_other_sources_are_ignored():
    det = EstimatorMonitor(CALIB)
    ev = [e for i in range(200) for e in det.observe(ekf(compass=0.8), [], "D", i * 0.02)]
    assert [e.class_hint for e in ev] == ["compass_anomaly"]
    det = EstimatorMonitor(CALIB)
    other = mav2.MAVLink(None, srcSystem=42, srcComponent=1)  # not the autopilot
    assert feed(det, [0.9] * 300, src=other) == []
    assert [e for i in range(300) for e in det.observe(ekf(pos=0.9), [], "U", i * 0.02)] == []  # uplink


def test_learning_meets_the_budget_and_leaves_constant_ratios_off():
    rng = np.random.default_rng(0)
    t = np.arange(0, 3600, 0.02)
    series = []
    for _ in range(2):
        s = {k: (t, np.zeros_like(t)) for k in estimator.RATIOS}
        s["pos_horiz_variance"] = (t, 0.2 + 0.05 * np.abs(rng.normal(size=len(t))))
        v = 0.2 + np.zeros_like(t)
        v[5000:5200] = 0.7  # one 4 s clean excursion per hour
        s["velocity_variance"] = (t, v)
        series.append(s)
    c = learn(series, budget_per_hour=0.5)
    assert c["meta"]["calibration_hours"] == 2.0
    assert set(c["meta"]["off"]) == {"pos_vert_variance", "compass_variance", "terrain_alt_variance"}
    assert c["thresholds"]["velocity_variance"] == 0.7  # 2 onsets in 2 h > 0.25/h below it; 0 at 0.7
    assert c["meta"]["false_onsets"] <= 0.5 * 2.0 and c["meta"]["upper95_per_hour"] > 0
    assert onsets(t, series[0]["velocity_variance"][1], 0.69, 2.0) == 1


def test_uses_no_simulator_truth_or_attack_code():
    src = Path(estimator.__file__).read_text()
    names = {a.name for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Import | ast.ImportFrom) for a in n.names}
    mods = {n.module for n in ast.walk(ast.parse(src)) if isinstance(n, ast.ImportFrom) and n.module}
    assert not ({"scenario", "attacks", "sitl", "link_sim"} & (names | mods))
    assert "SIMSTATE" not in src and "SIM_" not in src
