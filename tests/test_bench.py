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


RUNS = [  # attack 40-60 s, flight 100 s: clean time 0-40 s and 90-100 s (attack end + 30 s settling)
    # detected during the attack (onboard gps_spoofing 3 s after start); ArduPilot only at release
    doc("a2_gps_drift-s5001", gps(), [ep(43.0, "gps_spoofing", 3)], [ep(62.0, "gps_spoofing", 2, "baseline")]),
    # detected at release (4 s after the end, within the 10 s grace); a false alarm before the attack,
    # a secondary (other-class) detection during it, and a late false alarm after the settling time
    doc(
        "a2_gps_drift-s5002",
        gps(),
        [
            ep(20.0, "dos", 2, "ground", ["excess_loss"]),
            ep(50.0, "dos", 2, "ground"),
            ep(64.0, "gps_spoofing", 3),
            ep(95.0, "telemetry_manipulation", 2, "ground", ["commit_timeout"]),
        ],
    ),
    # missed: right class on the wrong agent (secondary), expected class too late for the grace
    # but inside the settling time (neither), and an advisory only
    doc(
        "a2_gps_drift-s5003",
        gps(),
        [ep(45.0, "gps_spoofing", 3, "ground"), ep(75.0, "gps_spoofing", 3), ep(50.0, "gnss_integrity_advisory", 1)],
    ),
    # benign flight: one false alarm at 150 m (after t = 50 s), one advisory, and ground-phase false
    # alarms before takeoff and after touchdown (flight 100 s)
    doc(
        "b1_calm-s5001",
        None,
        [
            ep(60.0, "telemetry_manipulation", 2, "ground"),
            ep(30.0, "x", 1),
            ep(-5.0, "x", 3),
            ep(105.0, "dos", 2, "ground", ["telemetry_gap"]),
        ],
    ),
]


def test_detection_during_incl_release_missed_advisory_and_secondary():
    s = bench.score(RUNS, "episodes", agent_check=True)["detection"]["a2_gps_drift"]
    got = [s[k] for k in ("runs", "detected_during", "detected_incl_release", "at_release", "missed", "advisory_only")]
    assert got == [3, 1, 2, 1, 1, 1] and s["detection_rate_during"] == 0.333
    assert s["secondary_episodes"] == 2  # ground dos during the attack; gps_spoofing on the wrong agent
    assert s["latency_during_s"] == {"median": 3.0, "p90": 3.0, "min": 3.0, "max": 3.0}
    assert s["latency_incl_release_s"] == {"median": 13.5, "p90": 21.9, "min": 3.0, "max": 24.0}
    b = bench.score(RUNS, "baseline_episodes", agent_check=False)["detection"]["a2_gps_drift"]
    assert (b["detected_during"], b["at_release"], b["latency_incl_release_s"]["min"]) == (0, 1, 22.0)


def test_false_alarms_before_the_attack_after_settling_on_benign_flights_and_on_the_ground():
    f = bench.score(RUNS, "episodes", agent_check=True)["false_alarms"]
    hours = (3 * (40 + 10) + 100) / 3600  # airborne clean time: attack flights 0-40 s and 90-100 s; benign 0-100 s
    assert f["count"] == 5 and f["advisories"] == 1 and f["clean_hours"] == round(hours, 3)
    assert sorted(a["t_start"] for a in f["list"]) == [-5.0, 20.0, 60.0, 95.0, 105.0]  # 95 s: after end + 30 s
    g = f["ground_phase_false_alarms"]
    assert g["count"] == 2 and sorted(a["t_start"] for a in g["list"]) == [-5.0, 105.0]
    assert {a["evidence_types"][0] for a in g["list"]} == {"x", "telemetry_gap"}
    assert f["per_hour"] == round(5 / hours, 3)  # ground-phase alarms add to the count, not to the hours
    assert f["upper95_per_hour"] == round(10.5130349 / hours, 3)  # chi2(0.95, 12) / 2 for 5 events
    by = f["by_distance"]
    assert by["0-100 m"]["count"] == 1 and by["100-200 m"]["count"] == 2  # 20 s at 0 m; 60 s, 95 s at 150 m
    assert by["on_ground"]["count"] == 2 and by["on_ground"]["clean_hours"] == 0.0
    assert by["0-100 m"]["clean_hours"] == round((3 * 40 + 50) / 3600, 3)
    assert by["100-200 m"]["clean_hours"] == round((3 * 10 + 50) / 3600, 3)
    assert {a["evidence_types"][0] for a in f["list"]} == {"excess_loss", "x", "commit_timeout", "telemetry_gap"}


def test_an_alarm_inside_the_settling_time_is_not_false_but_one_after_it_is():
    late = [doc("a1_gps_jump-s9", gps(), [ep(89.0, "dos", 2, "ground"), ep(91.0, "dos", 2, "ground")])]
    m = bench.score(late, "episodes", agent_check=True)
    assert [a["t_start"] for a in m["false_alarms"]["list"]] == [91.0]
    assert m["detection"]["a1_gps_jump"]["secondary_episodes"] == 1  # 89 s <= end + 30 s


def test_splits_by_arming_and_distance_at_attack_start():
    runs = [doc("a1_gps_jump-s1", gps(30.0, 40.0), [ep(31.0, "gps_spoofing", 3)], armed=70.0)]
    runs.append(doc("a1_gps_jump-s2", gps(80.0, 90.0), [], armed=70.0, track=[[0.0, 0.0], [60.0, 450.0]]))
    m = bench.score(runs, "episodes", agent_check=True)
    assert m["detection_by_arming"]["gps_drift, before arming"]["detected_during"] == 1
    assert m["detection_by_arming"]["gps_drift, after arming"]["missed"] == 1
    assert set(m["detection_by_distance"]) == {"gps_drift, 0-100 m", "gps_drift, >400 m"}


def test_metrics_refuses_non_test_exports_and_writes_tables(tmp_path):
    for d in RUNS:
        (tmp_path / f"{d['run_id']}.json").write_text(json.dumps(d))
    m = bench.metrics(tmp_path)
    assert m["runs"] == 4 and m["attack_runs"] == 3 and "| a2_gps_drift | 3 | 1 | 2 | 1 | 2 |" in bench.markdown(m)
    assert (m["grace_s"], m["settle_s"]) == (10.0, 30.0)
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
