"""Router tests over UDP loopback: fake FC, fake GCS, fake IDS listener."""

import socket
import time

import pytest
from pymavlink import mavutil

from gaganrakshak.router import Router

MAV = mavutil.mavlink
FC, RADIO, IDS = 16100, 16101, 16102


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
    assert drain(gcs, 0.2), "no path FC -> GCS"  # udpin GCS learns the router's address here
    yield fc, gcs, ids, r
    r.stop()
    time.sleep(0.15)
    for c in (fc, gcs, r.a, r.b):
        c.close()
    ids.close()


def drain(conn, seconds=0.3):
    out, t0 = [], time.monotonic()
    while time.monotonic() - t0 < seconds:
        m = conn.recv_match(blocking=True, timeout=0.05)
        if m is not None:
            out.append(m)
    return out


def ids_frames(sock, seconds=0.3):
    out, t0 = [], time.monotonic()
    while time.monotonic() - t0 < seconds:
        try:
            out.append(sock.recv(4096))
        except TimeoutError:
            pass
    return out


def names(frames):
    p = MAV.MAVLink(None)
    p.robust_parsing = True
    return [(f[:1], p.parse_char(f[1:]).get_type()) for f in frames]


def test_sim_traffic_never_reaches_radio_or_ids(rig):
    fc, gcs, ids, _ = rig
    fc.mav.simstate_send(*[0] * 11)
    fc.mav.param_value_send(b"SIM_GPS1_GLTCH_X", 1.0, 9, 1000, 5)
    fc.mav.param_set_send(1, 1, b"SIM_WIND_SPD", 3.0, 9)  # a harness write routed onto this link
    fc.mav.param_value_send(b"FENCE_ENABLE", 1.0, 2, 1000, 6)
    got_gcs = [m.get_type() + getattr(m, "param_id", "") for m in drain(gcs)]
    got_ids = names(ids_frames(ids))
    assert "PARAM_VALUEFENCE_ENABLE" in got_gcs
    assert not any("SIM" in n for n in got_gcs)
    assert (b"D", "PARAM_VALUE") in got_ids
    assert not any(n == "SIMSTATE" for _, n in got_ids)
    assert sum(1 for _, n in got_ids if n == "PARAM_VALUE") == 1


def test_gcs_rate_request_is_answered_locally_and_shapes_downlink(rig):
    fc, gcs, ids, r = rig
    drain(gcs, 0.1)
    gcs.mav.request_data_stream_send(1, 1, MAV.MAV_DATA_STREAM_EXTRA1, 10, 1)
    time.sleep(0.1)
    assert not any(
        m.get_type() == "REQUEST_DATA_STREAM" and m.get_srcSystem() == 255 for m in drain(fc, 0.2)
    )  # the router's own request (sysid 1) is expected
    ids_frames(ids, 0.1)
    t0 = time.monotonic()
    while time.monotonic() - t0 < 1.0:  # FC streams ATTITUDE at 50 Hz for 1 s
        fc.mav.attitude_send(0, 0, 0, 0, 0, 0, 0)
        time.sleep(0.02)
    to_gcs = sum(m.get_type() == "ATTITUDE" for m in drain(gcs))
    to_ids = sum(n == "ATTITUDE" for _, n in names(ids_frames(ids)))
    assert 8 <= to_gcs <= 12, to_gcs
    assert to_ids >= 45, to_ids


def test_set_message_interval_is_acked_by_router(rig):
    fc, gcs, _, r = rig
    gcs.mav.command_long_send(
        1, 1, MAV.MAV_CMD_SET_MESSAGE_INTERVAL, 0, MAV.MAVLINK_MSG_ID_RAW_IMU, 200000, 0, 0, 0, 0, 0
    )
    acks = [m for m in drain(gcs) if m.get_type() == "COMMAND_ACK"]
    assert acks and acks[0].result == MAV.MAV_RESULT_ACCEPTED
    assert r.radio_hz["RAW_IMU"] == pytest.approx(5.0)
    assert not any(m.get_type() == "COMMAND_LONG" for m in drain(fc, 0.1))


def test_command_reaches_fc_and_is_mirrored_as_uplink(rig):
    fc, gcs, ids, _ = rig
    gcs.mav.heartbeat_send(MAV.MAV_TYPE_GCS, MAV.MAV_AUTOPILOT_INVALID, 0, 0, 0)
    gcs.mav.command_long_send(1, 1, MAV.MAV_CMD_NAV_LAND, 0, 0, 0, 0, 0, 0, 0, 0)
    got = drain(fc)
    assert any(m.get_type() == "COMMAND_LONG" and m.command == MAV.MAV_CMD_NAV_LAND for m in got)
    assert (b"U", "COMMAND_LONG") in names(ids_frames(ids))


def test_forwarding_survives_without_ids(rig):
    fc, gcs, ids, _ = rig
    ids.close()  # IDS process gone
    for _ in range(5):
        fc.mav.heartbeat_send(MAV.MAV_TYPE_QUADROTOR, MAV.MAV_AUTOPILOT_ARDUPILOTMEGA, 0, 0, 0)
        gcs.mav.command_long_send(1, 1, MAV.MAV_CMD_NAV_LAND, 0, 0, 0, 0, 0, 0, 0, 0)
    assert sum(m.get_type() == "HEARTBEAT" for m in drain(gcs)) >= 5
    assert sum(m.get_type() == "COMMAND_LONG" for m in drain(fc)) == 5
