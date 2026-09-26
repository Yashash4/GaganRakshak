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

    fast = stress.measure(tmp_path, make=lambda side, run: [RollFlagger()])
    assert fast["platform"] == "DGX Spark" and fast["mode"] == "fast"
    on = fast["agents"]["onboard"]
    assert on["messages"] == 75 and set(on["latency"]) == {"p50_ms", "p95_ms", "p99_ms", "max_ms"}
    assert on["first_alert"] == {"latency_s": 0.1, "class": "toy_class"}  # roll 0.9 from t = 1.0 s
    assert fast["agents"]["ground"]["first_alert"] is None and fast["peak_rss_mb"] > 0

    paced = stress.measure(tmp_path, paced=True, make=lambda side, run: [RollFlagger()])
    on = paced["agents"]["onboard"]
    assert 1.4 <= on["wall_s"] < 3.0  # 1.48 s of traffic released in real time
    assert on["lateness"]["p50_ms"] < 50 and len(on["lateness_max_per_10s_s"]) == 1
