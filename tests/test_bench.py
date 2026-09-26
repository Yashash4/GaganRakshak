import json

import pytest

from gaganrakshak import bench


def ep(t, cls, sev=2, agent="onboard", types=("x",)):
    return {"agent": agent, "class": cls, "severity": sev, "t_start": t, "t_end": t + 5, "evidence_types": list(types)}


def doc(run_id, attack=None, eps=(), base=(), flight_s=100.0, armed=70.0, track=None):
    return {
        "run_id": run_id,
        "split": "test",
        "status": "ok",
        "calibration": {"cpce.json": "h"},
        "attack": attack,
        "flight_s": flight_s,
        "physics": {"observable_s": 10.0, "armed_s": armed},
        "distance_track": track if track is not None else [[0.0, 0.0], [50.0, 150.0]],
        "episodes": list(eps),
        "baseline_episodes": list(base),
    }


def gps(start=40.0, end=60.0):
    return {"type": "gps_drift", "start_s": start, "end_s": end, "params": {}}


RUNS = [
    # detected during the attack (onboard gps_spoofing 3 s after start); ArduPilot only at release
    doc("a2_gps_drift-s5001", gps(), [ep(43.0, "gps_spoofing", 3)], [ep(62.0, "gps_spoofing", 2, "baseline")]),
    # detected only at release (within attack_end + 5 s); one false alarm before the attack starts
    doc("a2_gps_drift-s5002", gps(), [ep(20.0, "dos", 2, "ground", ["excess_loss"]), ep(64.0, "gps_spoofing", 3)]),
    # missed: right class on the wrong agent, too late, and an advisory only in the window
    doc(
        "a2_gps_drift-s5003",
        gps(),
        [ep(45.0, "gps_spoofing", 3, "ground"), ep(70.0, "gps_spoofing", 3), ep(50.0, "gnss_integrity_advisory", 1)],
    ),
    # benign flight: one false alarm at 120 m (after t = 50 s), one advisory, one before takeoff (ignored)
    doc("b1_calm-s5001", None, [ep(60.0, "telemetry_manipulation", 2, "ground"), ep(30.0, "x", 1), ep(-5.0, "x", 3)]),
]


def test_detection_during_at_release_missed_and_advisory():
    m = bench.score(RUNS, "episodes", agent_check=True)
    s = m["detection"]["a2_gps_drift"]
    assert (s["runs"], s["detected"], s["during"], s["at_release"], s["missed"], s["advisory_only"]) == (
        3,
        2,
        1,
        1,
        1,
        1,
    )
    assert s["latency_s"] == {"median": 13.5, "p90": 21.9, "min": 3.0, "max": 24.0}
    b = bench.score(RUNS, "baseline_episodes", agent_check=False)["detection"]["a2_gps_drift"]
    assert (b["detected"], b["at_release"], b["latency_s"]["min"]) == (1, 1, 22.0)


def test_false_alarms_use_clean_time_only_with_upper_bound_and_distance_bands():
    f = bench.score(RUNS, "episodes", agent_check=True)["false_alarms"]
    hours = (40 * 3 + 100) / 3600  # three attack flights up to attack start + one benign flight
    assert f["count"] == 2 and f["advisories"] == 1 and f["clean_hours"] == round(hours, 3)
    assert f["per_hour"] == round(2 / hours, 3)
    assert f["upper95_per_hour"] == round(6.2957936 / hours, 3)  # chi2(0.95, 6) / 2 for 2 events
    by = f["by_distance"]
    assert by["0-100 m"]["count"] == 1 and by["100-200 m"]["count"] == 1  # at 20 s (0 m) and 60 s (150 m)
    assert by["100-200 m"]["clean_hours"] == round(50 / 3600, 3)  # only the benign flight is past 50 s clean
    assert {a["evidence_types"][0] for a in f["list"]} == {"excess_loss", "x"}


def test_splits_by_arming_and_distance_at_attack_start():
    runs = [doc("a1_gps_jump-s1", gps(30.0, 40.0), [ep(31.0, "gps_spoofing", 3)], armed=70.0)]
    runs.append(doc("a1_gps_jump-s2", gps(80.0, 90.0), [], armed=70.0, track=[[0.0, 0.0], [60.0, 450.0]]))
    m = bench.score(runs, "episodes", agent_check=True)
    assert m["detection_by_arming"]["gps_drift, before arming"]["detected"] == 1
    assert m["detection_by_arming"]["gps_drift, after arming"]["missed"] == 1
    assert set(m["detection_by_distance"]) == {"gps_drift, 0-100 m", "gps_drift, >400 m"}


def test_metrics_refuses_non_test_exports_and_writes_tables(tmp_path):
    for d in RUNS:
        (tmp_path / f"{d['run_id']}.json").write_text(json.dumps(d))
    m = bench.metrics(tmp_path)
    assert m["runs"] == 4 and m["attack_runs"] == 3 and "| a2_gps_drift | 3 | 2 | 1 | 1 | 1 |" in bench.markdown(m)
    (tmp_path / "x.json").write_text(json.dumps({**RUNS[0], "split": "validation"}))
    with pytest.raises(ValueError):
        bench.metrics(tmp_path)


def test_test_plan_covers_every_group_with_test_split_and_unique_ids():
    plans = bench.plan_test(n=2, m=1)
    groups = {bench.group_of(p) for p in plans}
    assert {
        "a1_gps_jump",
        "a3h_set_mode",
        "a5h_flood_gcs_sysid",
        "a2_gps_drift-r0.25",
        "a2n_gps_drift_naive-r2.0",
    } <= groups
    assert "a2a_gps_drift_accel-a0.005-early" in groups and "b4_gnss_glitch" in groups
    assert all(p["split"] == "test" and p["seed"] >= 5001 for p in plans)
    early = next(p for p in plans if p["run_id"] == "a2a_gps_drift_accel-a0.05-early-s5001")
    assert early["attack"]["start_s"] == 20.0 and early["attack"]["params"]["accel_ms2"] == 0.05
    assert next(p for p in plans if p["run_id"].startswith("a3h_set_mode"))["variant"] == "held_out"
    assert next(p for p in plans if p["run_id"] == "a2_gps_drift-r0.1-s5002")["attack"]["params"]["rate_ms"] == 0.1
    assert len(plans) == 2 * (10 + 4 + 10 + 5) + 7
