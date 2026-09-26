import random

from pymavlink.dialects.v20 import ardupilotmega as mav

import gaganrakshak  # noqa: F401
from gaganrakshak import crypto
from gaganrakshak.commit import CommitRx, CommitTx
from gaganrakshak.link_monitor import LinkMonitor

SEED, PUB = crypto.generate_keypair()


def parse(buf):
    p = mav.MAVLink(None)
    p.robust_parsing = True
    return p.parse_char(buf)


def downlink(seconds=40, per_s=20):
    """Heartbeat 1 Hz + attitude, committed each second, as the onboard router sends them."""
    fc = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    tx = CommitTx(SEED)
    tx.flush(0.0)
    out = []
    for s in range(seconds):
        for i in range(per_s):
            m = (mav.MAVLink_heartbeat_message(2, 3, 0, 0, 4, 3) if i == 0
                 else mav.MAVLink_attitude_message(s * 1000 + i, 0, 0, 0, 0, 0, 0))
            buf = m.pack(fc)
            fc.seq = (fc.seq + 1) % 256
            tx.add(buf, parse(buf))
            out.append((s + i / per_s, buf, False))
        out += [(s + 1.0, c, True) for c in tx.flush(s + 1.0)]
    return out


def run(stream, distance_m=0.0, extra=(), **kw):
    rx = CommitRx(PUB)
    lm = LinkMonitor(rx, **kw)
    lm.distance_m = distance_m
    ev = []
    items = sorted([(t, b, False) for t, b, _ in stream] + [(t, b, True) for t, b in extra], key=lambda x: x[0])
    tick = 0.0
    for t, buf, _ in items:
        while tick <= t:
            ev += lm.tick(tick)
            tick += 0.1
        msg = parse(buf)
        rx.observe(msg, [], "D", t)
        ev += lm.observe(msg, [], "D", t)
    return [e.evidence_type for e in ev], lm


def lossy(stream, p, seed=1, window=None):
    rng = random.Random(seed)
    return [x for x in stream if not ((window is None or window[0] <= x[0] < window[1]) and rng.random() < p)]


def test_normal_loss_near_home_is_quiet():
    kinds, lm = run(lossy(downlink(), 0.05))
    assert kinds == [] and lm.last["observed"] < 0.15


def test_heavy_loss_near_home_is_excess_loss():
    kinds, _ = run(lossy(downlink(), 0.6, window=(15, 30)))
    assert kinds.count("excess_loss") == 1


def test_same_loss_at_radio_range_is_expected():
    kinds, _ = run(lossy(downlink(), 0.5, window=(15, 30)), distance_m=500, d50_m=500, scale_m=60)
    assert kinds == []


def test_heartbeat_gap_is_reported():
    stream = [x for x in downlink() if not 20 <= x[0] < 26]  # 6 s total outage
    assert "telemetry_gap" in run(stream)[0]


def test_radio_buffer_congestion():
    radio = mav.MAVLink(None, srcSystem=51, srcComponent=68)
    rs = [(10.0 + k, mav.MAVLink_radio_status_message(200, 200, 5, 0, 0, 0, 0).pack(radio)) for k in range(6)]
    assert run(downlink(), extra=rs)[0].count("radio_congestion") == 1
