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


def _uplink(tmp_path, onboard, ground, t0=1000.0):
    """Synthetic uplink recordings: (scenario t, frame) lists for onboard_U and ground_U."""
    import struct

    for name, frames in (("onboard_U.tlog", onboard), ("ground_U.tlog", ground)):
        with open(tmp_path / name, "wb") as f:
            for t, buf in frames:
                f.write(struct.pack(">Q", int((t0 + t) * 1e6)) + buf)
    return t0


def _cmd(seq, command=400, gcs=True):  # 400 = MAV_CMD_COMPONENT_ARM_DISARM
    from pymavlink.dialects.v20 import ardupilotmega as mav2

    m = mav2.MAVLink(None, srcSystem=255 if gcs else 254, srcComponent=190)
    m.seq = seq
    return mav2.MAVLink_command_long_message(1, 1, command, 0, 0, 0, 0, 0, 0, 0, 0).pack(m)


def _episode(types, t=50.0):
    return {
        "agent": "onboard",
        "class": "command_injection",
        "severity": 2,
        "t_start": t,
        "t_end": t,
        "evidence_types": types,
    }


def test_a_genuine_lost_signature_is_an_old_sizing_artefact_with_its_matched_frames(tmp_path):
    import hashlib

    from gaganrakshak.export import lost_signature_evidence, old_sizing, uplink_commands

    disarm = _cmd(7)
    t0 = _uplink(tmp_path, onboard=[(49.6, disarm)], ground=[(49.5, disarm)])
    on, gnd = uplink_commands(tmp_path, t0)
    for types in (["unsigned_command"], ["unsafe_command", "unsigned_command"]):  # lost signature; genuine disarm
        ep = _episode(types)
        assert lost_signature_evidence(ep)
        matched, why = old_sizing(ep, on, gnd)
        assert why == "matched" and matched == [
            {"frame_sha256_8": hashlib.sha256(disarm).hexdigest()[:8], "onboard_t": 49.6, "ground_t": 49.5}
        ]
    assert not lost_signature_evidence(_episode(["unsafe_command"]))  # no lost signature involved
    assert not lost_signature_evidence(_episode(["unsigned_command", "bad_signature"]))


def test_an_injected_or_replayed_frame_is_never_an_artefact(tmp_path):
    from gaganrakshak.export import old_sizing, uplink_commands

    genuine, injected = _cmd(7), _cmd(8, command=21, gcs=False)  # an attacker's LAND
    t0 = _uplink(tmp_path, onboard=[(49.6, genuine), (49.9, injected)], ground=[(49.5, genuine)])
    matched, why = old_sizing(_episode(["unsigned_command"]), *uplink_commands(tmp_path, t0))
    assert matched == [] and why == "a received command frame the GCS never sent"
    t0 = _uplink(tmp_path, onboard=[(49.6, genuine), (49.8, genuine)], ground=[(49.5, genuine)])  # an extra copy
    matched, why = old_sizing(_episode(["unsigned_command"]), *uplink_commands(tmp_path, t0))
    assert matched == [] and why == "a command frame received more often than the GCS sent it"
    t0 = _uplink(tmp_path, onboard=[], ground=[(49.5, genuine)])
    assert old_sizing(_episode(["unsigned_command"]), *uplink_commands(tmp_path, t0))[0] == []  # nothing to match


def test_old_sizing_marks_applies_the_whole_rule_to_a_recorded_run(tmp_path):
    from gaganrakshak.export import old_sizing_marks

    disarm, injected = _cmd(7), _cmd(9, command=21, gcs=False)
    t0 = _uplink(tmp_path, onboard=[(49.6, disarm), (80.2, injected)], ground=[(49.5, disarm)])
    (tmp_path / "labels.json").write_text(json.dumps({"t0_wall": t0}))
    eps = [
        _episode(["unsafe_command", "unsigned_command"], 50.0),  # genuine disarm, signature lost: marked
        _episode(["unsigned_command"], 80.5),  # injected frame: kept
        _episode(["unsafe_command"], 50.0),  # no lost signature: kept
    ]
    marks = old_sizing_marks(tmp_path, eps, "before-b747b3e")
    assert list(marks) == [0] and marks[0][0]["onboard_t"] == 49.6
    assert old_sizing_marks(tmp_path, eps, "unknown") == {}  # flown after the fix: every alarm counts
