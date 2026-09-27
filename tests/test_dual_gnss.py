"""Second-GNSS-reference extension: the detector, its learning, the plans, and that the attacker
models can never touch the reference receiver."""

import math
import re
from pathlib import Path

import numpy as np

from gaganrakshak import dual_bench
from gaganrakshak.dual_gnss import M_PER_DEG, DualGnssMonitor, Separation, learn

PKG = Path(__file__).resolve().parent.parent / "gaganrakshak"
LAT0, LON0 = -35.36, 149.16


class Msg:
    def __init__(self, name, t, n=0.0, e=0.0, vel=0, cog=0, fix=3, src=1):
        self.name, self.src, self.fix_type = name, src, fix
        self.time_usec = int(t * 1e6)
        self.lat = int((LAT0 + n / M_PER_DEG) * 1e7)
        self.lon = int((LON0 + e / (M_PER_DEG * math.cos(math.radians(LAT0)))) * 1e7)
        self.vel, self.cog = vel, cog

    def get_type(self):
        return self.name

    def get_srcSystem(self):  # noqa: N802 (pymavlink's name)
        return self.src


def fly(det, offset_at, seconds=60.0):
    """GPS1 and GPS2 at 5 Hz, GPS1 displaced by offset_at(t) metres north."""
    out = []
    for i in range(int(seconds * 5)):
        t = i / 5
        det.observe(Msg("GPS_RAW_INT", t, n=offset_at(t)), [], "D", t)
        out += det.observe(Msg("GPS2_RAW", t + 0.02), [], "D", t + 0.02)
    return out


def test_separation_carries_gps1_to_the_reference_fix_time():
    s = Separation()
    s.observe(Msg("GPS_RAW_INT", 10.0, vel=500, cog=0))  # 5 m/s north
    d = s.observe(Msg("GPS2_RAW", 10.2, n=1.0))  # the reference fix 0.2 s later, 1 m north
    assert abs(d) < 0.05
    assert s.observe(Msg("GPS2_RAW", 11.0)) is None  # too far apart in time: not compared
    assert s.observe(Msg("COMMAND_ACK", 11.0)) is None  # any other message is ignored


def test_reports_once_only_after_the_separation_persists():
    det = DualGnssMonitor({"threshold_m": 10.0, "persist_s": 5.0})
    assert fly(det, lambda t: 12.0 if 20 <= t < 23 else 0.0) == []  # a 3 s excursion: not persistent
    det = DualGnssMonitor({"threshold_m": 10.0, "persist_s": 5.0})
    ev = fly(det, lambda t: 0.5 * max(0.0, t - 20))  # drift from 20 s at 0.5 m/s: above 10 m at 40 s
    assert len(ev) == 1 and ev[0].evidence_type == "gnss_reference_disagreement"
    assert ev[0].class_hint == "gps_spoofing" and 45.0 <= ev[0].t <= 45.5


def test_learned_threshold_meets_the_share_on_clean_flights():
    rng = np.random.default_rng(1)
    t = np.arange(0, 3600, 0.2)
    series = [(t, np.abs(rng.normal(0, 3, t.size)))]
    calib = learn(series, 1.0, 0.2, persist_s=5.0)
    assert calib["meta"]["false_onsets"] <= 0.2 and calib["threshold_m"] < 25


def test_attacker_models_never_write_the_reference_receiver():
    assert "GPS2" not in (PKG / "attacks.py").read_text()
    src = (PKG / "scenario.py").read_text()
    writes = re.findall(r'param_set_send\("SIM_GPS2_(\w+)"', src)
    assert sorted(writes) == ["GLTCH_X", "GLTCH_Y"]  # only the reference's own error process
    assert "gm2" in src.split('"SIM_GPS2_GLTCH_X"')[1].split("\n")[0]  # the reference error, not an attack offset


def test_extension_plans():
    test = dual_bench.plan_test()
    assert len(test) == 150 and len({p["run_id"] for p in test}) == 150
    assert all(p["gnss2"] and p["split"] == "test" and 6001 <= p["seed"] <= 6010 for p in test)
    assert not any("a2a" in p["run_id"] for p in test)
    cal = dual_bench.plan_calibration()
    assert all(p["split"] == "calibration" and p["seed"] >= 7001 and not p["attack"] for p in cal)
    from gaganrakshak.bench import _plan, _spec

    assert "gnss2" not in _plan(_spec("b1_calm"), 5001)  # base plans are unchanged
