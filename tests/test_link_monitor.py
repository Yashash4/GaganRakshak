import math
import random
import subprocess
import sys
from pathlib import Path

from pymavlink.dialects.v20 import ardupilotmega as mav

import gaganrakshak  # noqa: F401
from gaganrakshak import crypto
from gaganrakshak.commit import CommitRx, CommitTx
from gaganrakshak.link_monitor import LinkMonitor, LossCurve, onsets

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
            m = (
                mav.MAVLink_heartbeat_message(2, 3, 0, 0, 4, 3)
                if i == 0
                else mav.MAVLink_attitude_message(s * 1000 + i, 0, 0, 0, 0, 0, 0)
            )
            buf = m.pack(fc)
            fc.seq = (fc.seq + 1) % 256
            tx.add(buf, parse(buf))
            out.append((s + i / per_s, buf, False))
        out += [(s + 1.0, c, True) for c in tx.flush(s + 1.0)]
    return out


# learned from calibration: little loss near home, heavy loss beyond 300 m
CURVES = {"loss": LossCurve(50.0, [0.08, 0.08, 0.1, 0.15, 0.3, 0.6, 0.9, 1.0])}


def run(stream, distance_m=0.0, extra=(), curves=CURVES, **kw):
    rx = CommitRx(PUB)
    lm = LinkMonitor(rx, curves=curves, **kw)
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
    kinds, lm = run(lossy(downlink(), 0.03))
    assert kinds == [] and max(x for _, _, x in lm.samples) < 0.08


def test_heavy_loss_near_home_is_excess_loss():
    kinds, _ = run(lossy(downlink(), 0.6, window=(15, 30)))
    assert kinds.count("excess_loss") == 1


def test_same_loss_at_radio_range_is_expected():
    kinds, _ = run(lossy(downlink(), 0.5, window=(15, 30)), distance_m=320)
    assert kinds == []


def test_heartbeat_gap_is_reported():
    stream = [x for x in downlink() if not 20 <= x[0] < 26]  # 6 s total outage
    assert "telemetry_gap" in run(stream)[0]


def test_radio_buffer_congestion():
    radio = mav.MAVLink(None, srcSystem=51, srcComponent=68)
    rs = [(10.0 + k, mav.MAVLink_radio_status_message(200, 200, 5, 0, 0, 0, 0).pack(radio)) for k in range(6)]
    assert run(downlink(), extra=rs)[0].count("radio_congestion") == 1


def test_curve_fit_is_monotone_with_floor_and_meets_budget():
    rng = random.Random(3)
    samples = [(d, max(0.0, rng.gauss(0.02 + 0.5 * (d > 300), 0.02))) for d in range(0, 400, 2) for _ in range(5)]
    c = LossCurve.fit(samples, k=3)
    assert c.upper == sorted(c.upper) and c.upper[0] >= 0.05
    assert c.upper_at(100) < 0.2 and c.upper_at(350) > 0.5 and c.upper_at(5000) == c.upper[-1]
    series = [(i, d, x) for i, (d, x) in enumerate(samples)]
    assert onsets(series, LossCurve.fit(samples, k=6)) <= onsets(series, LossCurve.fit(samples, k=0))


def test_monitor_has_no_radio_model():
    """The expectation is learned; the monitor must not use the simulator's loss model."""
    code = "import sys, gaganrakshak.link_monitor; assert 'gaganrakshak.link_sim' not in sys.modules"
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0
    src = (Path(__file__).parent.parent / "gaganrakshak" / "link_monitor.py").read_text()
    assert "link_sim" not in src.replace("link_sim's", "")


def test_heartbeat_gap_normal_at_range_is_quiet():
    stream = [x for x in downlink() if not 20 <= x[0] < 26]  # 6 s silence far out: a fade
    assert "telemetry_gap" not in run(stream, distance_m=320)[0]


def gpi(fc, n_m, t_ms=0):
    return mav.MAVLink_global_position_int_message(
        t_ms, int((-35.36 + n_m / 111320) * 1e7), 1491652300, 584000, 20000, 0, 0, 0, 0
    ).pack(fc)


def test_falsified_far_position_does_not_excuse_loss():
    """Telemetry manipulation seen by the commitments: the reported distance is not trusted,
    so heavy loss is judged against the nearest band (A4 'far away' + jamming)."""
    stream = lossy(downlink(), 0.5, window=(15, 30))
    rx = CommitRx(PUB)
    lm = LinkMonitor(rx, curves=CURVES)
    lm.distance_m = 320  # what the falsified telemetry claims
    rx.t_last_manipulation = 5.0
    ev = []
    for t, buf, _ in stream:
        msg = parse(buf)
        rx.observe(msg, [], "D", t)
        ev += lm.observe(msg, [], "D", t)
    assert [e.evidence_type for e in ev] == ["excess_loss"] and ev[0].metadata["distance_trusted"] is False


def test_implausible_position_jump_is_not_trusted():
    fc = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    lm = LinkMonitor(CommitRx(PUB), curves=CURVES)
    lm.observe(parse(gpi(fc, 0)), [], "D", 0.0)
    lm.observe(parse(gpi(fc, 5)), [], "D", 1.0)
    assert lm.trusted_distance(1.0)[1]
    lm.observe(parse(gpi(fc, 400)), [], "D", 2.0)  # 395 m in 1 s
    assert lm.trusted_distance(2.0) == (0.0, False)


def test_outside_calibrated_range_is_marked_once():
    curves = {"loss": LossCurve(50.0, [0.1, 0.2], {"max_distance_m": 100.0})}
    lm = LinkMonitor(CommitRx(PUB), curves=curves)
    lm.distance_m = 150
    ev = lm.tick(1.0) + lm.tick(1.1)
    assert [(e.evidence_type, e.severity) for e in ev] == [("outside_calibrated_range", 0)]


def test_silence_limit_follows_loss_band():
    lm = LinkMonitor(CommitRx(PUB), curves=CURVES)
    assert lm.silence_limit(0) == 1 + math.log(1 / 3600) / math.log(0.08)  # ~4.2 s near home
    assert lm.silence_limit(320) > 15  # 90 % loss: long silences are normal


def test_onboard_gnss_evidence_makes_the_ground_distrust_the_reported_distance():
    """A slow GNSS spoof moves the reported position plausibly; only the onboard physics sees it.
    While its confirmed spoof is open (forwarded one window later) the ground uses the nearest band,
    however long the spoof lasts; once cleared, the reported distance is trusted again."""
    lm = LinkMonitor(None, onboard_gnss=[[100.0, 400.0], [500.0, None]], forward_latency_s=1.0)
    lm.distance_m = 350.0
    assert lm.trusted_distance(100.5) == (350.0, True)  # not yet received
    assert lm.trusted_distance(101.5) == (0.0, False) and lm.trusted_distance(390.0) == (0.0, False)
    assert lm.trusted_distance(402.0) == (350.0, True)  # cleared
    assert lm.trusted_distance(900.0) == (0.0, False)  # still open
