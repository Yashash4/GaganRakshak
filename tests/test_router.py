"""Router tests over UDP loopback: fake FC, fake GCS, fake IDS listener.

Every wait is for an event (the expected frame arrives) with a generous deadline, not a fixed
window, so a busy machine makes the tests slower, not wrong. Absence checks rely on ordering:
each router direction is one thread, so frames sent earlier arrive (or are dropped) first."""

import socket
import time

import pytest
from pymavlink import mavutil

from gaganrakshak.router import Router

MAV = mavutil.mavlink
FC, RADIO, IDS = 16100, 16101, 16102
DEADLINE_S = 20.0


@pytest.fixture
def rig():
    fc = mavutil.mavlink_connection(f"udpout:127.0.0.1:{FC}", source_system=1, source_component=1)
    gcs = mavutil.mavlink_connection(f"udpin:127.0.0.1:{RADIO}", source_system=255, source_component=190)
    ids = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ids.bind(("127.0.0.1", IDS))
    ids.settimeout(0.05)
    r = Router(f"udpin:127.0.0.1:{FC}", f"udpout:127.0.0.1:{RADIO}", IDS, onboard=True)
    fc.mav.heartbeat_send(MAV.MAV_TYPE_QUADROTOR, MAV.MAV_AUTOPILOT_ARDUPILOTMEGA, 0, 0, 0)
    r.start()
    fc.mav.heartbeat_send(MAV.MAV_TYPE_QUADROTOR, MAV.MAV_AUTOPILOT_ARDUPILOTMEGA, 0, 0, 0)
    assert until(gcs, lambda got: got), "no path FC -> GCS"  # udpin GCS learns the router's address here
    yield fc, gcs, ids, r
    r.stop()
    time.sleep(0.15)
    for c in (fc, gcs, r.a, r.b):
        c.close()
    ids.close()


def until(conn, done, deadline_s=DEADLINE_S):
    """Messages from a pymavlink connection until done(messages) or the deadline."""
    out, t0 = [], time.monotonic()
    while not done(out) and time.monotonic() - t0 < deadline_s:
        m = conn.recv_match(blocking=True, timeout=0.05)
        if m is not None:
            out.append(m)
    return out


def drain(conn, seconds=0.3):
    return until(conn, lambda _: False, seconds)


def ids_until(sock, done, deadline_s=DEADLINE_S):
    """(direction, type) of mirrored frames until done(list) or the deadline."""
    p = MAV.MAVLink(None)
    p.robust_parsing = True
    out, t0 = [], time.monotonic()
    while not done(out) and time.monotonic() - t0 < deadline_s:
        try:
            f = sock.recv(4096)
        except TimeoutError:
            continue
        out.append((f[:1], p.parse_char(f[1:]).get_type()))
    return out


def test_sim_traffic_never_reaches_radio_or_ids(rig):
    fc, gcs, ids, _ = rig
    fc.mav.simstate_send(*[0] * 11)
    fc.mav.param_value_send(b"SIM_GPS1_GLTCH_X", 1.0, 9, 1000, 5)
    fc.mav.param_set_send(1, 1, b"SIM_WIND_SPD", 3.0, 9)  # a harness write routed onto this link
    fc.mav.param_value_send(b"FENCE_ENABLE", 1.0, 2, 1000, 6)  # sent last: everything before is settled

    def fence(ms):
        return any(getattr(m, "param_id", "") == "FENCE_ENABLE" for m in ms)

    got_gcs = [m.get_type() + getattr(m, "param_id", "") for m in until(gcs, fence)]
    got_ids = ids_until(ids, lambda got: (b"D", "PARAM_VALUE") in got)
    assert "PARAM_VALUEFENCE_ENABLE" in got_gcs
    assert not any("SIM" in n for n in got_gcs)
    assert (b"D", "PARAM_VALUE") in got_ids
    assert not any(n == "SIMSTATE" for _, n in got_ids)
    assert sum(1 for _, n in got_ids if n == "PARAM_VALUE") == 1


def test_downlink_shaping_passes_the_requested_rate():
    r = Router.__new__(Router)  # shaping only: no sockets
    r.radio_hz, r._last_tx = {"ATTITUDE": 10.0}, {}
    passed = sum(r._allow_downlink("ATTITUDE", k * 0.02) for k in range(50))  # 50 Hz for 1 s
    assert passed == 10


def test_gcs_rate_request_is_answered_locally_and_shapes_downlink(rig):
    fc, gcs, ids, r = rig
    gcs.mav.request_data_stream_send(1, 1, MAV.MAV_DATA_STREAM_EXTRA1, 10, 1)
    t0 = time.monotonic()
    while r.radio_hz.get("ATTITUDE") != 10 and time.monotonic() - t0 < DEADLINE_S:
        time.sleep(0.01)
    assert r.radio_hz.get("ATTITUDE") == 10
    assert not any(
        m.get_type() == "REQUEST_DATA_STREAM" and m.get_srcSystem() == 255 for m in drain(fc, 0.2)
    )  # the router's own request (sysid 1) is expected
    ids_until(ids, lambda _: False, 0.1)
    sent, t_first = 0, time.monotonic()
    while time.monotonic() - t_first < 1.0:  # FC streams ATTITUDE at 50 Hz for 1 s
        fc.mav.attitude_send(0, 0, 0, 0, 0, 0, 0)
        sent += 1
        time.sleep(0.02)
    to_ids = sum(n == "ATTITUDE" for _, n in ids_until(ids, lambda got: got.count((b"D", "ATTITUDE")) >= sent))
    to_gcs = sum(m.get_type() == "ATTITUDE" for m in drain(gcs, 0.5))
    elapsed = time.monotonic() - t_first
    assert to_ids == sent  # the IDS sees every message
    assert 1 <= to_gcs <= 1 + elapsed / 0.09 and to_gcs < sent / 2, (to_gcs, sent, elapsed)


def test_set_message_interval_is_acked_by_router(rig):
    fc, gcs, _, r = rig
    gcs.mav.command_long_send(
        1, 1, MAV.MAV_CMD_SET_MESSAGE_INTERVAL, 0, MAV.MAVLINK_MSG_ID_RAW_IMU, 200000, 0, 0, 0, 0, 0
    )
    acks = [
        m
        for m in until(gcs, lambda ms: any(m.get_type() == "COMMAND_ACK" for m in ms))
        if m.get_type() == "COMMAND_ACK"
    ]
    assert acks and acks[0].result == MAV.MAV_RESULT_ACCEPTED
    assert r.radio_hz["RAW_IMU"] == pytest.approx(5.0)
    assert not any(m.get_type() == "COMMAND_LONG" for m in drain(fc, 0.1))


def test_command_reaches_fc_and_is_mirrored_as_uplink(rig):
    fc, gcs, ids, _ = rig
    gcs.mav.heartbeat_send(MAV.MAV_TYPE_GCS, MAV.MAV_AUTOPILOT_INVALID, 0, 0, 0)
    gcs.mav.command_long_send(1, 1, MAV.MAV_CMD_NAV_LAND, 0, 0, 0, 0, 0, 0, 0, 0)
    got = until(fc, lambda ms: any(m.get_type() == "COMMAND_LONG" for m in ms))
    assert any(m.get_type() == "COMMAND_LONG" and m.command == MAV.MAV_CMD_NAV_LAND for m in got)
    assert (b"U", "COMMAND_LONG") in ids_until(ids, lambda got: (b"U", "COMMAND_LONG") in got)


def test_forwarding_survives_without_ids(rig):
    fc, gcs, ids, _ = rig
    ids.close()  # IDS process gone
    for _ in range(5):
        fc.mav.heartbeat_send(MAV.MAV_TYPE_QUADROTOR, MAV.MAV_AUTOPILOT_ARDUPILOTMEGA, 0, 0, 0)
        gcs.mav.command_long_send(1, 1, MAV.MAV_CMD_NAV_LAND, 0, 0, 0, 0, 0, 0, 0, 0)
    assert sum(m.get_type() == "HEARTBEAT" for m in until(gcs, lambda ms: len(ms) >= 5)) >= 5
    cmds = until(fc, lambda ms: sum(m.get_type() == "COMMAND_LONG" for m in ms) >= 5) + drain(fc, 0.3)
    assert sum(m.get_type() == "COMMAND_LONG" for m in cmds) == 5  # each exactly once


def test_onboard_router_reports_uplink_loss_after_each_commitment():
    from gaganrakshak import crypto
    from gaganrakshak.cmd_sign import LinkReports

    fc = mavutil.mavlink_connection("udpout:127.0.0.1:16200", source_system=1, source_component=1)
    gcs = mavutil.mavlink_connection("udpin:127.0.0.1:16201", source_system=255, source_component=190)
    seed, pub = crypto.generate_keypair()
    r = Router("udpin:127.0.0.1:16200", "udpout:127.0.0.1:16201", 16202, onboard=True, commit_key=seed)
    try:
        fc.mav.heartbeat_send(MAV.MAV_TYPE_QUADROTOR, MAV.MAV_AUTOPILOT_ARDUPILOTMEGA, 0, 0, 0)
        r.start()
        types: list = []
        t0 = time.monotonic()
        while time.monotonic() - t0 < DEADLINE_S and not (
            sum(m.get_type() == "GR_LINK_SIGNED" for m in types) >= 2
            and any(m.get_type() == "GR_COMMIT" for m in types)
        ):
            fc.mav.heartbeat_send(MAV.MAV_TYPE_QUADROTOR, MAV.MAV_AUTOPILOT_ARDUPILOTMEGA, 0, 0, 0)
            types += [m for m in drain(gcs, 0.2) if m.get_type().startswith("GR_")]
        links = [m for m in types if m.get_type() == "GR_LINK_SIGNED"]
        assert len(links) >= 2 and all(m.uplink_loss == 255 for m in links)  # no GCS traffic yet: unknown
        ground = LinkReports(pub)
        assert all(ground.accept(m, 0.0) for m in links)  # signed with the commitment key, counter rising
        assert any(m.get_type() == "GR_COMMIT" for m in types)
    finally:
        r.stop()
        time.sleep(0.15)
        for c in (fc, gcs, r.a, r.b):
            c.close()
