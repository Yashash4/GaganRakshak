import json

import pytest

from gaganrakshak.export import export_run


def test_export_failed_run_keeps_truth_and_no_episodes(tmp_path):
    run = tmp_path / "r"
    run.mkdir()
    events = [
        {"event": "takeoff", "t": 0.0, "wall": 1.0},
        {"event": "attack_start", "t": 30.1, "wall": 31.0},
        {"event": "waypoint", "t": 5.0, "wall": 6.0},
        {"event": "touchdown", "t": 95.5, "wall": 96.0},
    ]
    (run / "labels.json").write_text(
        json.dumps(
            {
                "run_id": "a1-s1",
                "scenario": "a1",
                "seed": 1,
                "split": "heldout",
                "status": "failed: x",
                "attack": {"type": "gps_jump", "start_s": 30.1, "end_s": 50.0, "params": {"offset_m": 20}},
                "events": events,
            }
        )
    )
    doc = json.loads(export_run(run, "test", tmp_path / "out").read_text())
    assert doc["variant"] == "held_out" and doc["flight_s"] == 95.5 and doc["episodes"] == []
    assert [e["event"] for e in doc["events"]] == ["takeoff", "attack_start", "touchdown"]
    assert all("wall" not in e for e in doc["events"])
    with pytest.raises(ValueError):
        export_run(run, "somewhere", tmp_path / "out")
