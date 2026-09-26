import json
from pathlib import Path

import pytest
import yaml

from gaganrakshak import sitl
from gaganrakshak.ids import Ids, run_replay
from gaganrakshak.scenario import resolve, run_many, run_ports

SCEN = Path(__file__).parent.parent / "scenarios"
ATTACK_SPEC = {"name": "x", "attack": {"type": "gps_jump", "start_s": [30, 60], "duration_s": [10, 20],
                                       "params": {"offset_m": [20, 50]}}}


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


@pytest.mark.skipif(not sitl.BINARY.exists(), reason="ArduPilot SITL not built")
def test_eight_parallel_runs(tmp_path):
    spec = yaml.safe_load((SCEN / "smoke.yaml").read_text())
    plans = [resolve(spec, s) for s in range(1, 9)]
    results = run_many(plans, tmp_path, workers=8)
    assert [r[1] for r in results] == ["ok"] * 8, results
    labels = [json.loads((tmp_path / p["run_id"] / "labels.json").read_text()) for p in plans]
    assert len({l["instance"] for l in labels}) == 8
    for p, l in zip(plans, labels):
        assert {k: l[k] for k in p} == p  # labels carry the exact resolved plan
        assert l["recorded_frames"]["onboard"] > 1000 and l["recorded_frames"]["ground"] > 100
        assert [e["event"] for e in l["events"]][0] == "takeoff" and l["events"][-1]["event"] == "end"
        for side in ("onboard", "ground"):  # recorded traffic replays cleanly through the IDS
            ids = run_replay(Ids([]), tmp_path / p["run_id"] / side)
            assert not ids.adapter.stats["unknown"], (p["run_id"], side, ids.adapter.stats["unknown"])
            assert sum(ids.adapter.stats["mapped"].values()) > 50
