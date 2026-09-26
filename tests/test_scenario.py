import json
from pathlib import Path

import pytest
import yaml

from gaganrakshak.cmd_sign import CmdVerifier
from gaganrakshak.commit import CommitRx
from gaganrakshak.ids import Ids, run_replay
from gaganrakshak.integrity import IntegrityMonitor, load_baseline
from gaganrakshak.link_monitor import LinkMonitor
from gaganrakshak.protocol import for_agent
from gaganrakshak.scenario import resolve, run_many, run_ports

SCEN = Path(__file__).parent.parent / "scenarios"
BASE = Path(__file__).parent.parent / "configs" / "baseline" / "ardupilot_copter_sitl"
ATTACK_SPEC = {
    "name": "x",
    "attack": {"type": "gps_jump", "start_s": [30, 60], "duration_s": [10, 20], "params": {"offset_m": [20, 50]}},
}


def test_same_seed_same_plan():
    spec = yaml.safe_load((SCEN / "b1_calm.yaml").read_text())
    assert json.dumps(resolve(spec, 3)) == json.dumps(resolve(spec, 3))
    assert resolve(spec, 3)["waypoints"] != resolve(spec, 4)["waypoints"]


def test_attack_window_drawn_within_bounds_and_reproducible():
    a = [resolve(ATTACK_SPEC, s)["attack"] for s in range(50)]
    assert all(30 <= x["start_s"] <= 60 and 10 <= x["end_s"] - x["start_s"] <= 20 for x in a)
    assert all(20 <= x["params"]["offset_m"] <= 50 for x in a)
    assert a[7] == resolve(ATTACK_SPEC, 7)["attack"]


def test_instance_ports_disjoint():
    used = [p for i in range(16) for p in run_ports(i).values()]
    assert len(used) == len(set(used))


@pytest.mark.sitl
def test_eight_parallel_runs(tmp_path):
    spec = yaml.safe_load((SCEN / "smoke.yaml").read_text())
    plans = [resolve(spec, s) for s in range(1, 9)]
    results = run_many(plans, tmp_path, workers=8)
    assert [r[1] for r in results] == ["ok"] * 8, results
    labels = [json.loads((tmp_path / p["run_id"] / "labels.json").read_text()) for p in plans]
    assert len({lab["instance"] for lab in labels}) == 8
    for p, lab in zip(plans, labels, strict=True):
        assert {k: lab[k] for k in p} == p  # labels carry the exact resolved plan
        assert lab["recorded_frames"]["onboard"] > 1000 and lab["recorded_frames"]["ground"] > 100
        assert [e["event"] for e in lab["events"]][0] == "takeoff" and lab["events"][-1]["event"] == "end"
        run = tmp_path / p["run_id"]
        verifier = CmdVerifier(bytes.fromhex((run / "ground_sign.pub").read_text()))
        commit_rx = CommitRx(bytes.fromhex((run / "onboard_commit.pub").read_text()))
        for side in ("onboard", "ground"):  # recorded traffic replays cleanly through the IDS
            baseline = load_baseline(BASE.with_suffix(".json"), bytes.fromhex(BASE.with_suffix(".pub").read_text()))
            dets = (
                [for_agent(side), verifier, IntegrityMonitor(baseline, verifier)]
                if side == "onboard"
                else [for_agent(side), commit_rx, LinkMonitor(commit_rx)]
            )
            ids = run_replay(Ids(dets), tmp_path / p["run_id"] / side)
            assert ids.alerts == [], (p["run_id"], side, ids.alerts[:3])  # clean runs: no alarms
            assert not ids.adapter.stats["unknown"], (p["run_id"], side, ids.adapter.stats["unknown"])
            assert sum(ids.adapter.stats["mapped"].values()) > 50
        assert verifier.verified >= 5  # every pilot command (mode, arm, takeoff, targets) signed
        st = commit_rx.stats
        assert st["match"] > 500 and st["altered"] == st["unexpected"] == 0, st


def test_benign_glitch_windows_are_deterministic_and_inside_the_flight():
    spec = yaml.safe_load((SCEN / "b4_gnss_glitch.yaml").read_text())
    a, b = resolve(spec, 5)["benign"], resolve(spec, 5)["benign"]
    assert a == b and a["type"] == "gnss_glitch" and 1 <= len(a["windows"]) <= 3
    assert all(0 < s < e < spec["duration_s"] for s, e in a["windows"])
    assert resolve(yaml.safe_load((SCEN / "b1_calm.yaml").read_text()), 5)["benign"] is None


def test_every_scenario_attack_type_is_registered():
    from gaganrakshak.attacks import ATTACKS

    for f in sorted(SCEN.glob("*.yaml")):
        attack = yaml.safe_load(f.read_text()).get("attack")
        assert attack is None or attack["type"] in ATTACKS, f.name


def test_accelerating_spoof_offset_and_velocity_are_consistent():
    """Position offset a t^2/2 and velocity offset a t along the bearing, only inside the window."""
    import threading

    from gaganrakshak.attacks import ATTACKS

    class Run:
        plan = {
            "attack": {
                "type": "gps_drift_accel",
                "start_s": 10.0,
                "end_s": 110.0,
                "params": {"accel_ms2": 0.02, "bearing_deg": 90.0},
            }
        }
        t0, _stop = None, threading.Event()
        gnss_attack_offset = gnss_attack_velocity = None

    run = Run()
    ATTACKS["gps_drift_accel"](run)
    assert run.gnss_attack_offset(5.0) == (0.0, 0.0) and run.gnss_attack_velocity(5.0) == (0.0, 0.0)
    n, e = run.gnss_attack_offset(60.0)
    vn, ve = run.gnss_attack_velocity(60.0)
    assert abs(n) < 1e-9 and abs(e - 0.5 * 0.02 * 50**2) < 1e-9  # due east
    assert abs(vn) < 1e-9 and abs(ve - 0.02 * 50) < 1e-9
    assert run.gnss_attack_offset(120.0) == (0.0, 0.0)
