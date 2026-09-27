import math

from verify import check_calibration, poisson_upper, verify


def _run(rid, attack=None, eps=(), start=50.0, end=90.0, flight=3600.0, status="ok"):
    ev = [] if attack is None else [{"event": "attack_start", "t": start}, {"event": "attack_end", "t": end}]
    return {
        "run_id": rid,
        "status": status,
        "attack": attack,
        "events": ev,
        "flight_s": flight,
        "episodes": [dict(e) for e in eps],
    }


def test_rule_of_three_for_zero_alarms():
    assert math.isclose(poisson_upper(0, 1.0), -math.log(0.05), rel_tol=1e-6)  # ≈ 3.0 per hour


def test_detection_latency_and_false_alarms():
    runs = [
        _run("b1", eps=[{"class": "dos", "t_start": 10.0}]),  # benign alarm → FA
        _run("a1", {"type": "gps_jump"}, [{"class": "gps_spoofing", "t_start": 52.0, "agent": "onboard"}]),
        _run("a1b", {"type": "gps_jump"}, [{"class": "dos", "t_start": 60.0}]),  # wrong class during → miss + secondary
        _run(
            "a3",
            {"type": "command_injection"},
            [
                {"class": "command_injection", "t_start": 30.0},  # before start → FA
                {"class": "command_injection", "t_start": 50.5},
            ],
        ),
        _run("x", status="failed", eps=[{"class": "dos", "t_start": 1.0}]),  # ignored
    ]
    r = verify(runs)
    assert r["per_attack"]["gps_jump"] == {
        "runs": 2,
        "detected": 1,
        "detection_rate": 0.5,
        "detected_during_attack": 1,
        "advisory_only": 0,
        "detection_rate_during_attack": 0.5,
        "latency_p50_s": 2.0,
        "latency_p95_s": 2.0,
    }
    assert r["per_attack"]["command_injection"]["detected"] == 1
    assert r["false_alarms"] == 2  # b1 benign + a3 before start
    assert r["secondary_detections"] == {"gps_jump->dos": 1}
    assert r["flight_hours"] == 4.0
    assert r["ground_phase_false_alarms"] == 0


def test_detection_after_end_within_grace_counts():
    r = verify([_run("a", {"type": "jamming"}, [{"class": "dos", "t_start": 95.0}])])
    assert r["per_attack"]["jamming"]["detected"] == 1


def test_low_severity_episodes_are_advisories_not_alarms():
    r = verify(
        [
            _run(
                "b",
                eps=[
                    {"class": "gnss_integrity_advisory", "t_start": 5.0, "severity": 1},
                    {"class": "dos", "t_start": 9.0, "severity": 2},
                ],
            )
        ]
    )
    assert r["false_alarms"] == 1 and r["advisories_all_runs"] == 1


def test_attack_window_from_attack_fields_when_events_missing():
    run = {
        "run_id": "a",
        "status": "ok",
        "attack": {"type": "jamming", "start_s": 40.0, "end_s": 50.0},
        "events": [],
        "flight_s": 100.0,
        "episodes": [{"class": "dos", "t_start": 42.0, "severity": 2}],
    }
    assert verify([run])["per_attack"]["jamming"]["latency_p50_s"] == 2.0


def test_release_only_detection_is_not_during_attack():
    r = verify([_run("a", {"type": "jamming"}, [{"class": "dos", "t_start": 95.0}])])  # end 90, grace 10
    pa = r["per_attack"]["jamming"]
    assert pa["detected"] == 1 and pa["detected_during_attack"] == 0


def test_calibration_check_flags_missing_and_mixed_artefacts():
    ok = {"cpce.json": "a", "link_curves.json": "b"}
    assert check_calibration([{"run_id": "r1", "calibration": ok}, {"run_id": "r2", "calibration": ok}]) == []
    p = check_calibration(
        [
            {"run_id": "r1", "calibration": {"cpce.json": "a"}},
            {"run_id": "r2", "calibration": {"cpce.json": "z", "link_curves.json": "b"}},
        ]
    )
    assert any("missing" in x for x in p) and any("different hashes" in x for x in p)


def test_clean_hours_include_pre_attack_time():
    runs = [
        _run("b", flight=3600.0),
        _run("a", {"type": "jamming"}, [{"class": "dos", "t_start": 60.0}], start=1800.0, end=1900.0, flight=3600.0),
    ]
    r = verify(runs)
    assert r["clean_hours"] == round((3600 + 1800 + (3600 - 1930)) / 3600, 3)  # benign + pre + post-settle


def test_expected_agent_required_and_ground_phase_alarms_counted():
    wrong_agent = _run("a", {"type": "gps_jump"}, [{"class": "gps_spoofing", "t_start": 52.0, "agent": "ground"}])
    r = verify([wrong_agent])
    assert r["per_attack"]["gps_jump"]["detected"] == 0 and r["secondary_detections"] == {"gps_jump->gps_spoofing": 1}
    pre_takeoff = _run("b", eps=[{"class": "dos", "t_start": -5.0}], flight=100.0)
    r = verify([pre_takeoff])
    assert r["false_alarms"] == 1 and r["ground_phase_false_alarms"] == 1


def test_marked_artefacts_listed_apart_not_counted():
    mark = {
        "class": "command_injection",
        "t_start": 10.0,
        "severity": 2,
        "artefact": "old_sizing",
        "evidence_types": ["unsigned_command", "unsafe_command"],
        "matched_uplink": ["h1"],
    }
    old = _run("b", eps=[mark, {"class": "dos", "t_start": 20.0, "severity": 2}])
    old["flown_at"] = "before-b747b3e"
    r = verify([old])
    assert r["false_alarms"] == 1 and len(r["artefact_episodes"]) == 1
    new = _run("n", eps=[mark])  # flown_at unknown -> the mark is rejected and the alarm counts
    r = verify([new])
    assert r["false_alarms"] == 1 and len(r["rejected_artefact_marks"]) == 1


def test_artefact_mark_without_uplink_match_is_rejected():
    e = {
        "class": "command_injection",
        "t_start": 10.0,
        "severity": 2,
        "artefact": "old_sizing",
        "evidence_types": ["unsigned_command"],
    }
    run = _run("b", eps=[e])
    run["flown_at"] = "before-b747b3e"
    r = verify([run])
    assert r["false_alarms"] == 1 and len(r["rejected_artefact_marks"]) == 1


def test_calibration_check_flags_mixed_or_dirty_detector_code():
    ok = {"cpce.json": "a", "link_curves.json": "b"}
    p = check_calibration(
        [
            {"run_id": "r1", "calibration": ok, "evaluated_with": "abc"},
            {"run_id": "r2", "calibration": ok, "evaluated_with": "def-dirty"},
        ]
    )
    assert any("different detector code" in x for x in p) and any("dirty" in x for x in p)


def test_calibration_check_flags_mixed_crypto_ablation():
    ok = {"cpce.json": "a", "link_curves.json": "b"}
    p = check_calibration([{"run_id": "r1", "calibration": ok}, {"run_id": "r2", "calibration": ok, "crypto": False}])
    assert any("crypto" in x for x in p)


def test_per_scenario_splits_far_and_drift_rate():
    a = _run(
        "a",
        {"type": "gps_drift", "params": {"rate_ms": 2.0}},
        [{"class": "gps_spoofing", "t_start": 55.0, "agent": "onboard"}],
    )
    a["scenario"] = "a2_gps_drift"
    b = _run("b", {"type": "jamming"}, [])
    b["scenario"] = "a9_jamming_far"
    r = verify([a, b])
    assert r["per_scenario"]["a2_gps_drift@rate_ms=2"]["detected_during_attack"] == 1
    assert r["per_scenario"]["a9_jamming_far"]["detected"] == 0
