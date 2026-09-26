"""ArduPilot MAVLink -> platform-independent ``Sample`` stream.

Every message type is either mapped, ignored on purpose (``IGNORED`` gives the reason) or
counted as unknown in ``stats`` — nothing is dropped silently. Fields the message does not
carry, or carries as "unknown" sentinels, become ``None``.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Optional

from pymavlink import mavutil

from .sample import (
    Attitude, Baro, Command, EstimatorRatios, Gnss, Imu, LinkStats, ParamValue, Sample,
    Status, StatusText, VersionInfo,
)

G = 9.80665
MG = G / 1000.0  # RAW_IMU / SCALED_IMU* acceleration unit (milli-g)

COMMAND_MSGS = {
    "COMMAND_LONG", "COMMAND_INT", "SET_MODE", "PARAM_SET", "SET_POSITION_TARGET_LOCAL_NED",
    "SET_POSITION_TARGET_GLOBAL_INT", "MISSION_COUNT", "MISSION_ITEM_INT", "MISSION_ITEM",
    "MISSION_CLEAR_ALL", "MISSION_SET_CURRENT", "FILE_TRANSFER_PROTOCOL",
    "RC_CHANNELS_OVERRIDE", "MANUAL_CONTROL",
}

IGNORED = {
    "BAD_DATA": "undecodable bytes; counted by the protocol layer",
    "SIMSTATE": "simulator ground truth; never visible to the IDS",
    "AHRS": "autopilot-internal estimate", "AHRS2": "autopilot-internal estimate",
    "AHRS3": "autopilot-internal estimate",
    "GLOBAL_POSITION_INT": "EKF output (GNSS-fused); detectors use raw GNSS",
    "LOCAL_POSITION_NED": "EKF output (GNSS-fused)", "WIND": "EKF wind estimate",
    "VFR_HUD": "derived display values", "NAV_CONTROLLER_OUTPUT": "controller internals",
    "BATTERY_STATUS": "battery covered by SYS_STATUS", "POWER_STATUS": "board power",
    "ESC_TELEMETRY_1_TO_4": "ESC housekeeping", "SERVO_OUTPUT_RAW": "actuator outputs",
    "RC_CHANNELS": "RC input housekeeping", "VIBRATION": "housekeeping", "MEMINFO": "housekeeping",
    "SYSTEM_TIME": "housekeeping", "TIMESYNC": "housekeeping", "TERRAIN_REPORT": "housekeeping",
    "TERRAIN_REQUEST": "housekeeping", "TERRAIN_DATA": "housekeeping",
    "MISSION_CURRENT": "housekeeping", "HOME_POSITION": "static reference",
    "GPS_GLOBAL_ORIGIN": "static reference", "COMMAND_ACK": "handled by the protocol layer",
    "REQUEST_DATA_STREAM": "read-only request; handled by the router",
    "PARAM_ERROR": "rejected-write reply; the write attempt itself is seen as PARAM_SET",
    "PARAM_REQUEST_LIST": "read-only request", "PARAM_REQUEST_READ": "read-only request",
    "MISSION_REQUEST_LIST": "read-only request", "MISSION_REQUEST_INT": "read-only request",
    "MISSION_REQUEST": "read-only request", "MISSION_ACK": "handshake", "MISSION_ITEM_REACHED": "housekeeping",
    "POSITION_TARGET_GLOBAL_INT": "controller setpoint echo", "POSITION_TARGET_LOCAL_NED": "controller setpoint echo",
    "ATTITUDE_QUATERNION": "duplicate of ATTITUDE", "SCALED_IMU3": "third IMU not used",
    "EXTENDED_SYS_STATE": "housekeeping", "AOA_SSA": "housekeeping", "MCU_STATUS": "housekeeping",
    "SCALED_PRESSURE3": "third barometer not used",
    "HEARTBEAT(GCS)": "GCS keepalive, no vehicle state; the protocol layer tracks its source",
    "PARAM_VALUE(SIM_*)": "simulator-only parameter; does not exist on a real flight controller",
    "GR_CMD_SIG": "IDS command signature; verified by cmd_sign, not vehicle state",
}


def _none_if(v, *sentinels):
    return None if v in sentinels else v


class ArduPilotAdapter:
    def __init__(self, uav_id: int = 1):
        self.uav_id = uav_id
        self.mode = "UNKNOWN"
        self.armed = False
        self.stats = {"mapped": Counter(), "ignored": Counter(), "unknown": Counter()}

    def convert(self, msg, t: float) -> list[Sample]:
        """Convert one pymavlink message received at monotonic time ``t``."""
        name = self._key(msg)
        payloads = self._payloads(msg, name)
        if payloads is None:
            bucket = "ignored" if name in IGNORED else "unknown"
            self.stats[bucket][name] += 1
            return []
        self.stats["mapped"][name] += 1
        hdr = msg.get_header() if hasattr(msg, "get_header") else None
        seq = msg.get_seq() if hdr else None
        msg_id = msg.get_msgId() if name != "BAD_DATA" else None
        return [Sample(t=t, uav_id=self.uav_id, payload=p, t_boot=self._t_boot(msg),
                       msg_id=msg_id, seq=seq) for p in payloads]

    @staticmethod
    def _key(msg) -> str:
        """Message type, split where one type needs two different treatments."""
        name = msg.get_type()
        if name == "HEARTBEAT" and (msg.type == mavutil.mavlink.MAV_TYPE_GCS
                                    or msg.autopilot == mavutil.mavlink.MAV_AUTOPILOT_INVALID):
            return "HEARTBEAT(GCS)"
        if name == "PARAM_VALUE" and msg.param_id.startswith("SIM_"):
            return "PARAM_VALUE(SIM_*)"
        return name

    @staticmethod
    def _t_boot(msg) -> Optional[float]:
        if hasattr(msg, "time_boot_ms"):
            return msg.time_boot_ms / 1000.0
        if msg.get_type() == "RAW_IMU":  # ArduPilot fills time_usec with time since boot
            return msg.time_usec / 1e6
        return None

    def _payloads(self, m, name):  # noqa: C901 — flat dispatch, one branch per message
        if name in ("RAW_IMU", "SCALED_IMU2"):
            return [Imu(m.xacc * MG, m.yacc * MG, m.zacc * MG,
                        m.xgyro / 1000.0, m.ygyro / 1000.0, m.zgyro / 1000.0)]
        if name == "GPS_RAW_INT":
            vel = _none_if(m.vel, 65535)
            cog = _none_if(m.cog, 65535)
            vn = ve = None
            if vel is not None and cog is not None:
                vn = vel / 100.0 * math.cos(math.radians(cog / 100.0))
                ve = vel / 100.0 * math.sin(math.radians(cog / 100.0))
            h_acc = getattr(m, "h_acc", 0)
            v_acc = getattr(m, "v_acc", 0)
            return [Gnss(lat=m.lat / 1e7, lon=m.lon / 1e7, alt=m.alt / 1000.0, vn=vn, ve=ve, vd=None,
                         fix_type=m.fix_type, satellites=_none_if(m.satellites_visible, 255),
                         h_acc=h_acc / 1000.0 if h_acc else None,
                         v_acc=v_acc / 1000.0 if v_acc else None)]
        if name in ("SCALED_PRESSURE", "SCALED_PRESSURE2"):
            return [Baro(pressure_pa=m.press_abs * 100.0, alt_m=None, temperature_c=m.temperature / 100.0)]
        if name == "ATTITUDE":
            return [Attitude(m.roll, m.pitch, m.yaw)]
        if name == "HEARTBEAT":
            self.mode = mavutil.mode_string_v10(m)
            self.armed = bool(m.base_mode & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED)
            return [Status(self.mode, self.armed)]
        if name == "SYS_STATUS":
            v = _none_if(m.voltage_battery, 65535, 0)
            return [Status(self.mode, self.armed, battery_v=v / 1000.0 if v else None)]
        if name == "EKF_STATUS_REPORT":
            return [EstimatorRatios(m.velocity_variance, m.pos_horiz_variance,
                                    m.pos_vert_variance, m.compass_variance)]
        if name == "RADIO_STATUS":
            return [LinkStats(rssi=m.rssi, remote_rssi=m.remrssi, rx_errors=m.rxerrors)]
        if name == "PARAM_VALUE":
            return [ParamValue(m.param_id, m.param_value)]
        if name == "AUTOPILOT_VERSION":
            git = bytes(m.flight_custom_version).rstrip(b"\x00").decode("ascii", "replace")
            return [VersionInfo(m.flight_sw_version, git)]
        if name == "STATUSTEXT":
            return [StatusText(m.severity, m.text)]
        if name in COMMAND_MSGS:
            return [self._command(m, name)]
        return None

    @staticmethod
    def _command(m, name) -> Command:
        params = {k: v for k, v in m.to_dict().items() if k != "mavpackettype"}
        label = name
        if name in ("COMMAND_LONG", "COMMAND_INT"):
            enum = mavutil.mavlink.enums["MAV_CMD"].get(m.command)
            label = enum.name if enum else f"MAV_CMD_{m.command}"
        return Command(command=label, src_sysid=m.get_srcSystem(), src_compid=m.get_srcComponent(),
                       params=params)
