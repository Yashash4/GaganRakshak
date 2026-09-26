import json
import struct

from pymavlink.dialects.v20 import ardupilotmega as mav2

from gaganrakshak import stress
from gaganrakshak.evidence import EvidenceEvent, Severity
from gaganrakshak.sample import Attitude

T0 = 1_000_000.0


def write_tlog(path, msgs):
    mav = mav2.MAVLink(None, srcSystem=1, srcComponent=1)
    with open(path, "wb") as f:
        for t, m in msgs:
            f.write(struct.pack(">Q", int(t * 1e6)) + m.pack(mav))


class RollFlagger:
    """Toy detector: evidence when the roll exceeds 0.5 rad."""

    def observe(self, msg, samples, direction, t):
        return [
            EvidenceEvent(t, 1, "toy", "roll", 1.0, Severity.HIGH, "toy_class")
            for s in samples
            if isinstance(s.payload, Attitude) and s.payload.roll > 0.5
        ]


def toy_detectors(side, run):  # module level: the agent process imports it by name
    return [RollFlagger()]


def test_fast_and_paced_replay_measure_latency_backlog_and_alert_latency(tmp_path):
    mav = mav2.MAVLink(None)
    att = [(T0 + i / 50, mav.attitude_encode(i * 20, 0.9 if i >= 50 else 0.0, 0, 0, 0, 0, 0)) for i in range(75)]
    write_tlog(tmp_path / "onboard_D.tlog", att)
    write_tlog(tmp_path / "ground_D.tlog", att[:10])
    labels = {
        "run_id": "synthetic",
        "t0_wall": T0,
        "attack": {"type": "toy"},
        "events": [{"event": "attack_start", "t": 0.9}, {"event": "attack_end", "t": 1.4}],
    }
    (tmp_path / "labels.json").write_text(json.dumps(labels))

    fast = stress.measure(tmp_path, make=toy_detectors)
    assert fast["platform"] == "DGX Spark" and fast["mode"] == "fast"
    on = fast["agents"]["onboard"]
    assert on["messages"] == 75 and set(on["latency"]) == {"p50_ms", "p95_ms", "p99_ms", "max_ms", "n"}
    assert on["latency_by_type"]["ATTITUDE"]["n"] == 75 and on["recorded_s"] == 1.48
    assert set(on["detector_s"]) == {"RollFlagger"} and "physics" not in on
    assert on["timing_buffers_mb"] == 0.0  # 75 messages: a few hundred bytes of packed timings
    assert on["first_alert"] == {"latency_s": 0.1, "class": "toy_class"}  # roll 0.9 from t = 1.0 s
    assert fast["agents"]["ground"]["first_alert"] is None and on["peak_rss_mb"] >= on["rss_start_mb"] > 0

    paced = stress.measure(tmp_path, paced=True, make=toy_detectors)
    on = paced["agents"]["onboard"]
    assert on["wall_s"] >= 1.4  # 1.48 s of traffic released in real time, never faster
    assert (
        on["lateness"]["p50_ms"] >= 0 and len(on["lateness_max_per_10s_s"]) == 1
    )  # value depends on the machine's load


def test_physics_cost_is_split_into_new_gnss_fixes_and_repeats():
    mav = mav2.MAVLink(None)
    timed = stress.Timed(RollFlagger())
    for usec in (1, 1, 2, 2, 2, 3):
        timed.observe(mav.gps_raw_int_encode(usec, 3, 0, 0, 0, 0, 0, 0, 0, 10), [], "D", 0.0)
    assert len(timed.times["GPS_RAW_INT(new fix)"]) == 3 and len(timed.times["GPS_RAW_INT(repeat)"]) == 3
