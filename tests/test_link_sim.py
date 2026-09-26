"""link_sim: rate cap, loss and latency statistics, attacker hooks, synthetic RADIO_STATUS.

The channel model (rate cap, loss, latency) is driven on a simulated clock, so its statistics
do not depend on how busy the test machine is. The socket tests wait for events with generous
deadlines instead of fixed windows."""

import socket
import statistics
import time

import pytest
from pymavlink.dialects.v20 import ardupilotmega as mav2

from gaganrakshak.link_sim import DOWN, UP, Attacker, LinkConfig, LinkSim

AIR, GND = 16500, 16501
AC = mav2.MAVLink(None, srcSystem=1, srcComponent=1)
GCS = mav2.MAVLink(None, srcSystem=255, srcComponent=190)
DEADLINE_S = 20.0


def frame(i=0):
    return mav2.MAVLink_heartbeat_message(2, 3, 0, i % 256, 4, 3).pack(AC)  # 21 bytes


class Capture:
    """Stands in for the ground socket: records (simulated time, frame) of every send."""

    def __init__(self):
        self.now = 0.0
        self.sent = []

    def sendto(self, buf, addr):
        self.sent.append((self.now, buf))


def drive(cfg, offers, until, step=0.0005):
    """The link's main loop on a simulated clock (same steps as LinkSim.run): frames offered
    downlink at their times, due frames sent. Returns (sim, [(arrival time, frame)])."""
    sim = LinkSim(AIR, GND, cfg)
    sim.air.close()
    sim.gnd.close()
    cap = sim.gnd = Capture()
    offers = sorted(offers, key=lambda x: x[0])
    i, now = 0, 0.0
    while now <= until:
        cap.now = now
        while i < len(offers) and offers[i][0] <= now:
            sim._ingest(DOWN, offers[i][1], now)
            i += 1
        sim._send_due(now)
        now += step
    return sim, cap.sent


def rig(cfg, attacker=None):
    sim = LinkSim(AIR, GND, cfg, attacker).start()
    air = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # onboard router's radio port
    gnd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # ground router (udpin)
    gnd.bind(("127.0.0.1", GND))
    gnd.settimeout(0.05)
    return sim, air, gnd


def recv_until(sock, done, deadline_s=DEADLINE_S):
    """Receive (arrival time, frame) until done(frames) or the deadline."""
    out, t0 = [], time.monotonic()
    while not done(out) and time.monotonic() - t0 < deadline_s:
        try:
            buf = sock.recv(4096)
        except TimeoutError:
            continue
        out.append((time.monotonic(), buf))
    return out


def parsed(got):
    return [mav2.MAVLink(None).parse_char(b) for _, b in got]


def telemetry(got):
    """Drop the link's own RADIO_STATUS frames."""
    return [(t, b) for t, b in got if mav2.MAVLink(None).parse_char(b).get_type() != "RADIO_STATUS"]


@pytest.fixture
def cleanup():
    held = []
    yield held
    for sim, *socks in held:
        sim.stop()
        time.sleep(0.05)
        for s in (sim.air, sim.gnd, *socks):
            s.close()


def test_throughput_never_exceeds_cap():
    cfg = LinkConfig(latency_s=0.0, jitter_s=0.0)
    f = frame()
    offers = [(k * 0.02, f) for k in range(100) for _ in range(11)]  # ~2x capacity for 2 s: 11.5 vs 5.76 kB/s
    sim, got = drive(cfg, offers, until=3.0)
    span = got[-1][0] - got[0][0]
    rate = sum(len(b) for _, b in got) / span
    assert rate <= cfg.rate_bps / 10 * 1.03, rate
    assert rate >= cfg.rate_bps / 10 * 0.85, rate  # link saturated, not idle
    assert sim.dirs[DOWN].stats["overflow"] > 0


def test_loss_rate_reproduced():
    # fast link: this test measures loss only, not the rate cap
    offers = [(i * 0.0005, frame(i)) for i in range(2000)]
    sim, got = drive(LinkConfig(rate_bps=1e8, loss=0.2, latency_s=0.0, jitter_s=0.0, seed=7), offers, until=1.1)
    s = sim.dirs[DOWN].stats
    assert s["overflow"] == 0
    assert len(got) == s["sent"] == 2000 - s["lost"]
    expect = 1 - (1 - 0.2) ** (len(frame()) / 40)  # 20 % is stated for a 40-byte frame
    assert abs(s["lost"] / 2000 - expect) < 0.03, (s["lost"], expect)


def test_latency_reproduced():
    cfg = LinkConfig(latency_s=0.050, jitter_s=0.010)
    offers = [(i * 0.2, frame(i)) for i in range(100)]  # one at a time: no queueing
    _, got = drive(cfg, offers, until=20.5)
    assert len(got) == 100
    delays = [ta - t for (t, _), (ta, _) in zip(offers, got, strict=True)]
    expect = cfg.latency_s + cfg.airtime(len(frame()))
    assert statistics.mean(delays) == pytest.approx(expect, abs=0.005)
    assert max(delays) < expect + cfg.jitter_s + 0.001  # + one loop step
    assert min(delays) > expect - cfg.jitter_s - 1e-9


def test_distance_loss_and_rssi():
    sim = LinkSim(AIR, GND, LinkConfig(loss_d50_m=500, loss_scale_m=50))
    try:
        sim.distance_m = 0
        assert sim.loss_prob() < 0.001 and sim.rssi() == 200
        sim.distance_m = 500
        assert sim.loss_prob() == pytest.approx(0.5)
        assert sim.loss_prob(200) == pytest.approx(1 - 0.5**5)  # 5x longer frame, same bit errors
        sim.distance_m = 1000
        assert sim.loss_prob() > 0.99 and sim.rssi() == 120
    finally:
        sim.air.close()
        sim.gnd.close()


class Mitm(Attacker):
    """Drops heartbeats, alters ATTITUDE, injects a command uplink once."""

    def __init__(self):
        self.injected = False

    def on_frame(self, direction, buf, msg, now):
        if msg.get_type() == "HEARTBEAT":
            return []
        if msg.get_type() == "ATTITUDE":
            return [mav2.MAVLink_attitude_message(0, 1.0, 0, 0, 0, 0, 0).pack(AC)]
        return [buf]

    def tick(self, direction, now):
        if direction == UP and not self.injected:
            self.injected = True
            return [mav2.MAVLink_command_long_message(1, 1, 21, 0, 0, 0, 0, 0, 0, 0, 0).pack(GCS)]
        return []


def test_attacker_hooks(cleanup):
    sim, air, gnd = rig(LinkConfig(latency_s=0.0, jitter_s=0.0), Mitm())
    cleanup.append((sim, air, gnd))
    air.settimeout(0.05)
    air.sendto(frame(), ("127.0.0.1", AIR))  # link learns the air-side peer
    air.sendto(mav2.MAVLink_attitude_message(0, 0.0, 0, 0, 0, 0, 0).pack(AC), ("127.0.0.1", AIR))
    # a serial link never reorders: had the heartbeat passed, it would arrive before the attitude
    down = parsed(telemetry(recv_until(gnd, lambda g: telemetry(g))))
    assert [m.get_type() for m in down] == ["ATTITUDE"] and down[0].roll == 1.0
    up = parsed(recv_until(air, lambda g: any(m.get_type() == "COMMAND_LONG" for m in parsed(g))))
    assert any(m.get_type() == "COMMAND_LONG" and m.command == 21 for m in up)


def test_synthetic_radio_status(cleanup):
    t_start = time.monotonic()
    sim, air, gnd = rig(LinkConfig())
    cleanup.append((sim, air, gnd))
    got = recv_until(gnd, lambda g: len(g) >= 2)
    rs = [m for m in parsed(got) if m.get_type() == "RADIO_STATUS"]
    assert len(rs) == 2 and rs[0].get_srcSystem() == 51 and rs[0].rssi == 200
    assert rs[1].get_seq() == (rs[0].get_seq() + 1) % 256
    assert got[1][0] - t_start >= 2.0  # one per second, never faster
    assert sim.stats()["radio_status"] == "synthetic"
