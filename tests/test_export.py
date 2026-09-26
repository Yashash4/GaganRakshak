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
    assert doc["variant"] == "held_out" and doc["flight_s"] == 95.5
    assert doc["episodes"] == doc["baseline_episodes"] == []
    assert [e["event"] for e in doc["events"]] == ["takeoff", "attack_start", "touchdown"]
    assert all("wall" not in e for e in doc["events"])
    with pytest.raises(ValueError):
        export_run(run, "somewhere", tmp_path / "out")
    out = export_run(run, "validation", tmp_path / "out", source="batch/a1-s1")
    assert out == tmp_path / "out" / "validation" / "batch" / "a1-s1.json"  # same run id elsewhere stays apart
    doc = json.loads(out.read_text())
    assert doc["source"] == "batch/a1-s1" and doc["run_id"] == "a1-s1"


def test_export_records_calibration_files_and_keeps_test_seeds_out(tmp_path, monkeypatch):
    import gaganrakshak.export as ex

    calib = tmp_path / "cpce.json"
    calib.write_bytes(b"{}\n")
    monkeypatch.setattr(ex, "CPCE_CALIB", calib)
    monkeypatch.setattr(ex, "LINK_CURVES", tmp_path / "absent.json")
    monkeypatch.setattr(ex, "ESTIMATOR_CALIB", tmp_path / "absent.json")
    assert ex.calibration_used() == {"cpce.json": "0967ef424bce6791893e9a57bb952f80fd536e93"}  # git hash-object
    run = tmp_path / "t"
    run.mkdir()
    (run / "labels.json").write_text(json.dumps({"run_id": "x", "split": "test", "status": "ok", "events": []}))
    with pytest.raises(ValueError):
        export_run(run, "validation", tmp_path / "out")


def test_distance_track_is_about_1hz_from_home_after_takeoff(tmp_path):
    import struct

    from pymavlink.dialects.v20 import ardupilotmega as mav2

    from gaganrakshak.export import distance_track

    ap = mav2.MAVLink(None, srcSystem=1, srcComponent=1)
    t0, lat0, lon0 = 1000.0, -35.0, 149.0
    with open(tmp_path / "ground_D.tlog", "wb") as f:
        for i in range(-4, 21):  # 2 Hz from 2 s before takeoff; 1 m north per sample after it
            north = i * 1.0 if i >= 0 else 500.0  # fixes before takeoff must not set home
            lat = int((lat0 + north / 111194.93) * 1e7)
            m = ap.global_position_int_encode(0, lat, int(lon0 * 1e7), 0, 0, 0, 0, 0, 0)
            f.write(struct.pack(">Q", int((t0 + i * 0.5) * 1e6)) + m.pack(ap))
    tr = distance_track(tmp_path, t0)
    assert [t for t, _ in tr] == [float(k) for k in range(11)]
    assert [d for _, d in tr] == pytest.approx([2.0 * k for k in range(11)], abs=0.1)


def test_flown_at_uses_the_code_version_else_the_signature_sizing_fix_time():
    from gaganrakshak.export import SIGNATURE_SIZING_FIX_T, flown_at

    assert flown_at({"code_version": "abc1234", "t0_wall": 1.0}) == "abc1234"
    assert flown_at({"t0_wall": 1790458553.0}) == "before-b747b3e"  # a calib4 flight
    assert flown_at({"t0_wall": 1790463214.0}) == "unknown"  # the rehearsal: after the fix, untagged
    assert flown_at({"t0_wall": SIGNATURE_SIZING_FIX_T}) == "unknown"
    assert flown_at({}) == "unknown"
