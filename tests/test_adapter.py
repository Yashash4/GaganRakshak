from pathlib import Path

import pytest
from pymavlink import mavutil
from pymavlink.dialects.v20 import ardupilotmega as mav

from gaganrakshak.adapter import IGNORED, ArduPilotAdapter
from gaganrakshak.sample import (
    Attitude, Baro, Command, EstimatorRatios, Gnss, Imu, LinkStats, ParamValue, Status, StatusText,
    VersionInfo,
)

TLOG = Path(__file__).parent / "data" / "sitl_flight.tlog"
M = mav.MAVLink(None, srcSystem=1, srcComponent=1)


def roundtrip(msg):
    """Pack and parse, so the message carries a real header like one off the wire."""
    return M.parse_char(msg.pack(M))


def one(msg):
    out = ArduPilotAdapter().convert(roundtrip(msg), 1.0)
    assert len(out) == 1
    return out[0].payload


def test_imu_units():
    p = one(mav.MAVLink_raw_imu_message(0, 0, 0, -1000, 10, 20, -5, 0, 0, 0))
    assert isinstance(p, Imu)
    assert p.az == pytest.approx(-9.80665)
    assert p.gx == pytest.approx(0.010) and p.gz == pytest.approx(-0.005)


def test_gnss_velocity_and_unknown_sentinels():
    p = one(mav.MAVLink_gps_raw_int_message(0, 3, -353632610, 1491652300, 584000, 65535, 65535,
                                            500, 9000, 255))
    assert isinstance(p, Gnss)
    assert p.lat == pytest.approx(-35.363261) and p.alt == pytest.approx(584.0)
    assert p.vn == pytest.approx(0.0, abs=1e-9) and p.ve == pytest.approx(5.0)
    assert p.satellites is None and p.h_acc is None


def test_gnss_speed_unknown():
    p = one(mav.MAVLink_gps_raw_int_message(0, 3, 0, 0, 0, 100, 100, 65535, 65535, 10))
    assert p.vn is None and p.ve is None


def test_other_mapped_types():
    assert isinstance(one(mav.MAVLink_scaled_pressure_message(0, 1013.25, 0, 2500)), Baro)
    assert isinstance(one(mav.MAVLink_attitude_message(0, 0.1, 0.2, 0.3, 0, 0, 0)), Attitude)
    assert isinstance(one(mav.MAVLink_ekf_status_report_message(0, 0.1, 0.2, 0.3, 0.4, 0)),
                      EstimatorRatios)
    assert isinstance(one(mav.MAVLink_radio_status_message(200, 190, 0, 0, 0, 3, 0)), LinkStats)
    assert one(mav.MAVLink_param_value_message(b"FENCE_ENABLE", 1.0, 2, 100, 5)) == \
        ParamValue("FENCE_ENABLE", 1.0)
    assert one(mav.MAVLink_statustext_message(4, b"GPS Glitch")) == StatusText(4, "GPS Glitch")
    v = one(mav.MAVLink_autopilot_version_message(0, 0x04070100, 0, 0, 0, b"abcdef12", b"\0" * 8,
                                                  b"\0" * 8, 0, 0, 0))
    assert v == VersionInfo(0x04070100, "abcdef12")


def test_heartbeat_tracks_mode_and_arming():
    a = ArduPilotAdapter()
    hb = mav.MAVLink_heartbeat_message(mavutil.mavlink.MAV_TYPE_QUADROTOR,
                                       mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                                       mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED
                                       | mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 4, 4, 3)
    assert a.convert(roundtrip(hb), 0)[0].payload == Status("GUIDED", True)
    sys = a.convert(roundtrip(mav.MAVLink_sys_status_message(0, 0, 0, 0, 12600, -1, -1, 0, 0, 0, 0, 0, 0)), 0)
    assert sys[0].payload == Status("GUIDED", True, battery_v=12.6)


def test_command_from_gcs():
    c = one(mav.MAVLink_command_long_message(1, 1, mavutil.mavlink.MAV_CMD_NAV_LAND, 0, 0, 0, 0, 0, 0, 0, 0))
    assert isinstance(c, Command) and c.command == "MAV_CMD_NAV_LAND" and c.src_sysid == 1


def test_gcs_heartbeat_and_sim_params_ignored_not_unknown():
    a = ArduPilotAdapter()
    gcs = mav.MAVLink_heartbeat_message(mavutil.mavlink.MAV_TYPE_GCS,
                                        mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0, 3)
    sim = mav.MAVLink_param_value_message(b"SIM_GPS1_GLTCH_X", 1.0, 9, 1000, 5)
    assert a.convert(roundtrip(gcs), 0) == [] and a.convert(roundtrip(sim), 0) == []
    assert a.stats["ignored"] == {"HEARTBEAT(GCS)": 1, "PARAM_VALUE(SIM_*)": 1}
    assert not a.stats["unknown"] and not a.stats["mapped"]


def test_simstate_never_reaches_samples():
    a = ArduPilotAdapter()
    assert a.convert(roundtrip(mav.MAVLink_simstate_message(*[0] * 11)), 0) == []
    assert a.stats["ignored"]["SIMSTATE"] == 1


def test_replay_real_sitl_flight():
    """Every message in a real SITL flight is mapped or deliberately ignored — none unknown."""
    log = mavutil.mavlink_connection(str(TLOG))
    a = ArduPilotAdapter()
    samples = []
    while (msg := log.recv_msg()) is not None:
        samples += a.convert(msg, msg._timestamp)
    assert not a.stats["unknown"], dict(a.stats["unknown"])
    assert set(a.stats["ignored"]) <= set(IGNORED)
    kinds = {type(s.payload) for s in samples}
    assert {Imu, Gnss, Baro, Attitude, Status, EstimatorRatios, ParamValue, VersionInfo,
            StatusText} <= kinds
    assert "PARAM_VALUE(SIM_*)" in a.stats["ignored"]  # the SIM_ write was recorded and ignored
    assert not any(isinstance(s.payload, ParamValue) and s.payload.name.startswith("SIM_")
                   for s in samples)
    modes = {s.payload.mode for s in samples if isinstance(s.payload, Status)}
    assert {"GUIDED", "LAND"} <= modes
