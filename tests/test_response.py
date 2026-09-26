from pymavlink import mavutil
from pymavlink.dialects.v20 import ardupilotmega as mav

from gaganrakshak.response import ResponseMonitor

MAV = mavutil.mavlink
FC = mav.MAVLink(None, srcSystem=1, srcComponent=1)
GCS = mav.MAVLink(None, srcSystem=255, srcComponent=190)


def msg(m, sender):
    buf = m.pack(sender)
    sender.seq = (sender.seq + 1) % 256
    return mav.MAVLink(None).parse_char(buf)


def hb(mode_num):
    return msg(mav.MAVLink_heartbeat_message(2, 3, MAV.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED | 128, mode_num, 4, 3), FC)


def run(steps):
    """steps: (t, direction, message) -> evidence types"""
    rm = ResponseMonitor()
    return [e.evidence_type for t, d, m in steps for e in rm.observe(m, [], d, t)]


def test_commanded_mode_changes_are_explained():
    steps = [
        (0, "D", hb(4)),
        (10, "U", msg(mav.MAVLink_set_mode_message(1, 1, 5), GCS)),
        (10.5, "D", hb(5)),  # LOITER
        (20, "U", msg(mav.MAVLink_command_long_message(1, 1, MAV.MAV_CMD_NAV_LAND, 0, 0, 0, 0, 0, 0, 0, 0), GCS)),
        (20.4, "D", hb(9)),
    ]  # LAND
    assert run(steps) == []


def test_failsafe_notice_explains_a_mode_change():
    steps = [
        (0, "D", hb(4)),
        (5, "D", msg(mav.MAVLink_statustext_message(2, b"Radio Failsafe"), FC)),
        (5.5, "D", hb(6)),
    ]
    assert run(steps) == []


def test_mode_change_nobody_asked_for():
    steps = [(0, "D", hb(4)), (30, "D", hb(9))]  # LAND out of nowhere (injected on the radio link)
    assert run(steps) == ["uncommanded_mode_change"]


def test_stale_command_does_not_explain_a_later_change():
    steps = [(0, "D", hb(4)), (1, "U", msg(mav.MAVLink_set_mode_message(1, 1, 9), GCS)), (20, "D", hb(9))]
    assert run(steps) == ["uncommanded_mode_change"]
