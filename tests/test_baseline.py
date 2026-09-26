from pymavlink.dialects.v20 import ardupilotmega as mav2

from gaganrakshak.baseline import EKF_GPS_GLITCHING, episodes_from

M = mav2.MAVLink(None, srcSystem=1, srcComponent=1)
T0 = 1000.0


def ekf(flags=0x033F, vel=0.1, pos=0.1, compass=0.1):
    return M.ekf_status_report_encode(flags, vel, pos, 0.05, compass, 0.0)


def text(s, sev=2):
    return M.statustext_encode(sev, s.encode())


def hb(custom_mode):  # ArduCopter: 4 GUIDED, 6 RTL, 9 LAND
    return M.heartbeat_encode(2, 3, 217, custom_mode, 4)


def test_glitch_flag_and_innovation_ratios_are_one_gps_episode_in_scenario_time():
    msgs = [(T0 + t, ekf()) for t in range(0, 10)]
    msgs += [(T0 + 10.0, ekf(flags=0x033F | EKF_GPS_GLITCHING)), (T0 + 10.1, text("GPS Glitch or Compass error"))]
    msgs += [(T0 + 12.0, ekf(pos=1.7)), (T0 + 14.0, text("EKF3 lane switch 1"))]
    msgs += [(T0 + t, ekf()) for t in range(15, 40)]
    eps = episodes_from(msgs, T0)
    assert eps == [{"agent": "baseline", "class": "gps_spoofing", "severity": 2, "t_start": 10.0, "t_end": 14.0}]


def test_compass_ratio_is_not_counted_as_gnss():
    eps = episodes_from([(T0, ekf(compass=1.5)), (T0 + 20, ekf())], T0)
    assert [e["class"] for e in eps] == ["compass_anomaly"]


def test_failsafe_text_and_its_mode_change_are_a_high_dos_episode_but_a_plain_mode_change_is_not():
    msgs = [(T0, hb(4)), (T0 + 5, hb(9)), (T0 + 6, hb(4))]  # commanded LAND and back: no indicator
    msgs += [(T0 + 30, text("Radio Failsafe")), (T0 + 31, hb(6)), (T0 + 60, hb(6))]
    eps = episodes_from(msgs, T0)
    assert eps == [{"agent": "baseline", "class": "dos", "severity": 3, "t_start": 30.0, "t_end": 31.0}]


def test_quiet_run_has_no_episodes_and_open_episode_has_no_end():
    assert episodes_from([(T0 + t, ekf()) for t in range(30)], T0) == []
    assert episodes_from([(T0, ekf(vel=2.0)), (T0 + 3, ekf(vel=2.0))], T0)[0]["t_end"] is None
