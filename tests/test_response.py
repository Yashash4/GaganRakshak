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


class Verdicts:
    """Stands for the ground agent's CommitRx: verdict per received frame, by seq."""

    def __init__(self, by_seq):
        self.by_seq = by_seq

    def verdict(self, t_rx, seq, msgid):
        return self.by_seq.get(seq)


def run(steps, rx=None, until=None):
    """steps: (t, direction, message) -> evidence types (ticks after the last step until `until`)"""
    rm = ResponseMonitor(rx=rx)
    out = [e.evidence_type for t, d, m in steps for e in rm.observe(m, [], d, t)]
    if until is not None:
        out += [e.evidence_type for e in rm.tick(until)]
    return out


def test_commanded_mode_changes_are_explained():
    steps = [
        (0, "D", hb(4)),
        (10, "U", msg(mav.MAVLink_set_mode_message(1, 1, 5), GCS)),
        (10.5, "D", hb(5)),  # LOITER
        (20, "U", msg(mav.MAVLink_command_long_message(1, 1, MAV.MAV_CMD_NAV_LAND, 0, 0, 0, 0, 0, 0, 0, 0), GCS)),
        (20.4, "D", hb(9)),
    ]  # LAND
    assert run(steps) == []


def failsafe_then_land(text=b"Battery Failsafe", battery_pct=80):
    notice = msg(mav.MAVLink_statustext_message(2, text), FC)
    status = msg(mav.MAVLink_sys_status_message(0, 0, 0, 0, 11000, -1, battery_pct, 0, 0, 0, 0, 0, 0), FC)
    return notice, [(0, "D", hb(4)), (4, "D", status), (5, "D", notice), (5.5, "D", hb(9))]


def test_verified_failsafe_notice_explains_a_mode_change():
    notice, steps = failsafe_then_land()
    assert run(steps, rx=Verdicts({notice.get_seq(): "match"})) == ["excused_mode_change"]


def test_injected_failsafe_notice_does_not_hide_an_injected_mode_change():
    notice, steps = failsafe_then_land()
    assert run(steps, rx=Verdicts({notice.get_seq(): "unexpected"})) == ["uncommanded_mode_change"]


def test_judgement_waits_for_the_notice_verdict_then_decides():
    notice, steps = failsafe_then_land()
    assert run(steps, rx=Verdicts({}), until=8.0) == []  # verdict still awaited: nothing yet
    assert run(steps, rx=Verdicts({}), until=11.0) == ["uncommanded_mode_change"]  # never verified


def test_without_commitments_only_corroborated_notices_count():
    _, steps = failsafe_then_land(battery_pct=15)
    assert run(steps) == ["excused_mode_change"]  # SYS_STATUS shows the low battery the notice names
    _, steps = failsafe_then_land(battery_pct=80)
    assert run(steps, until=11.0) == ["uncommanded_mode_change"]


def test_mode_change_nobody_asked_for():
    steps = [(0, "D", hb(4)), (30, "D", hb(9))]  # LAND out of nowhere (injected on the radio link)
    assert run(steps) == ["uncommanded_mode_change"]


def test_stale_command_does_not_explain_a_later_change():
    steps = [(0, "D", hb(4)), (1, "U", msg(mav.MAVLink_set_mode_message(1, 1, 9), GCS)), (20, "D", hb(9))]
    assert run(steps) == ["uncommanded_mode_change"]


def test_compound_attack_excused_change_keeps_the_chain():
    """Jamming (a real telemetry outage) + an injected 'GCS failsafe' notice + an injected LAND: the
    outage corroborates the notice, so the change is excused, as a real failover would be. The
    jamming raises its own dos alarm in the link monitor; here the INFO record keeps the chain."""
    notice = msg(mav.MAVLink_statustext_message(2, b"GCS Failsafe"), FC)
    steps = [(0, "D", hb(4)), (1, "D", hb(4)), (5, "D", hb(4)), (5.2, "D", notice), (5.5, "D", hb(9))]  # 4 s gap
    rm = ResponseMonitor(rx=Verdicts({notice.get_seq(): "unexpected"}))
    ev = [e for t, d, m in steps for e in rm.observe(m, [], d, t)]
    assert [e.evidence_type for e in ev] == ["excused_mode_change"]
    assert ev[0].metadata["excused_by"] == "telemetry_outage" and ev[0].metadata["notice_verdict"] == "unexpected"


def target(lat_m_north):
    lat = -35.36 + lat_m_north / 111320.0
    return msg(
        mav.MAVLink_position_target_global_int_message(
            0, 6, 0xFFF8, int(lat * 1e7), 1491650000, 600.0, 0, 0, 0, 0, 0, 0, 0, 0
        ),
        FC,
    )


def servo(aux9):
    return msg(
        mav.MAVLink_servo_output_raw_message(0, 0, 1500, 1500, 1500, 1500, 0, 0, 0, 0, aux9, 0, 0, 0, 0, 0, 0, 0), FC
    )


def test_position_target_moved_without_a_request_is_flagged():
    move = [(0, "D", hb(4)), (20, "D", target(0)), (30, "D", target(50))]
    assert run(move) == ["uncommanded_target_change"]
    req = msg(
        mav.MAVLink_set_position_target_local_ned_message(0, 1, 1, 1, 0x0DF8, 50, 0, -20, 0, 0, 0, 0, 0, 0, 0, 0), GCS
    )
    assert run([(0, "D", hb(4)), (20, "D", target(0)), (29, "U", req), (30, "D", target(50))]) == []
    assert run([(0, "D", hb(4)), (20, "D", target(0)), (28, "D", hb(5)), (30, "D", target(50))]) != [
        "uncommanded_target_change"
    ]


def test_aux_output_changed_without_a_servo_command_is_flagged():
    assert run([(0, "D", hb(4)), (10, "D", servo(0)), (11, "D", servo(1900))]) == ["uncommanded_servo_output"]
    cmd = msg(mav.MAVLink_command_long_message(1, 1, MAV.MAV_CMD_DO_SET_SERVO, 0, 9, 1900, 0, 0, 0, 0, 0), GCS)
    assert run([(0, "D", hb(4)), (10, "D", servo(0)), (10.5, "U", cmd), (11, "D", servo(1900))]) == []


def test_mission_item_changes_follow_the_uploaded_mission_including_do_jump():
    """Items: 0 home, 1-2 waypoints, 3 DO_JUMP back to 1, 4 waypoint. Legitimate: 1->2, 2->1 (the
    jump), 2->4 (jump exhausted). Not legitimate: 1->4 with no set-current request."""

    def item(seq, command, p1=0.0):
        return msg(mav.MAVLink_mission_item_int_message(1, 1, seq, 3, command, 0, 1, p1, 0, 0, 0, 0, 0, 20, 0), GCS)

    def cur(seq):
        return msg(mav.MAVLink_mission_current_message(seq, 5, 0, 0), FC)

    upload = [
        (1, "U", item(0, 16)),
        (1, "U", item(1, 16)),
        (1, "U", item(2, 16)),
        (1, "U", item(3, 177, 1)),
        (1, "U", item(4, 16)),
    ]
    auto = [(0, "D", hb(4)), *upload, (2, "U", msg(mav.MAVLink_set_mode_message(1, 1, 3), GCS)), (2.5, "D", hb(3))]
    legit = [(20, "D", cur(1)), (40, "D", cur(2)), (60, "D", cur(1)), (80, "D", cur(2)), (100, "D", cur(4))]
    assert run(auto + legit) == []
    assert run(auto + [(20, "D", cur(1)), (40, "D", cur(4))]) == ["uncommanded_mission_change"]
