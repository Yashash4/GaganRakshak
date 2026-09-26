"""Inline MAVLink router (one per agent).

Onboard:  FC <-> router <-> radio.   Ground:  radio <-> router <-> GCS.

Forwards both ways and mirrors every message to the IDS process over local UDP as
``direction byte + raw MAVLink frame`` (b"D" = from the aircraft side, b"U" = from the GCS
side). The mirror is fire-and-forget: if the IDS is down, forwarding carries on.

The onboard router also shapes the downlink:
- asks the FC for all streams at ``fc_rate_hz`` so the IDS sees high-rate IMU;
- forwards each streamed message type to the radio no faster than the rate the GCS asked
  for (REQUEST_DATA_STREAM / SET_MESSAGE_INTERVAL are answered here, not passed to the FC);
- drops simulator-only traffic (SIMSTATE, SIM_* parameters) before the radio and the IDS:
  it would not exist on a real aircraft.

    python -m gaganrakshak.router --onboard --a tcp:127.0.0.1:5760 --b udpout:127.0.0.1:14600
    python -m gaganrakshak.router --a udpin:0.0.0.0:14600 --b udpout:127.0.0.1:14550 --ids-port 15601
"""

from __future__ import annotations

import argparse
import socket
import threading
import time
from collections import Counter, deque
from pathlib import Path

from pymavlink import mavutil
from pymavlink.dialects.v20 import ardupilotmega as mav2

from .cmd_sign import Signer, is_command
from .commit import CommitTx

MAV = mavutil.mavlink
ROUTER_SYSID, ROUTER_COMPID = 1, MAV.MAV_COMP_ID_ONBOARD_COMPUTER

# ArduPilot stream groups (GCS_MAVLink ap_message tables): which message types each
# MAV_DATA_STREAM id controls. Messages not listed are events and are never throttled.
STREAMS = {
    MAV.MAV_DATA_STREAM_RAW_SENSORS: {
        "RAW_IMU",
        "SCALED_IMU2",
        "SCALED_IMU3",
        "SCALED_PRESSURE",
        "SCALED_PRESSURE2",
        "SCALED_PRESSURE3",
    },
    MAV.MAV_DATA_STREAM_EXTENDED_STATUS: {
        "SYS_STATUS",
        "POWER_STATUS",
        "MCU_STATUS",
        "MEMINFO",
        "MISSION_CURRENT",
        "GPS_RAW_INT",
        "GPS2_RAW",
        "NAV_CONTROLLER_OUTPUT",
        "FENCE_STATUS",
        "POSITION_TARGET_GLOBAL_INT",
    },
    MAV.MAV_DATA_STREAM_POSITION: {"GLOBAL_POSITION_INT", "LOCAL_POSITION_NED"},
    MAV.MAV_DATA_STREAM_RC_CHANNELS: {"SERVO_OUTPUT_RAW", "RC_CHANNELS", "RC_CHANNELS_RAW"},
    MAV.MAV_DATA_STREAM_EXTRA1: {"ATTITUDE", "SIMSTATE", "AHRS2", "PID_TUNING"},
    MAV.MAV_DATA_STREAM_EXTRA2: {"VFR_HUD"},
    MAV.MAV_DATA_STREAM_EXTRA3: {
        "AHRS",
        "SYSTEM_TIME",
        "WIND",
        "RANGEFINDER",
        "DISTANCE_SENSOR",
        "TERRAIN_REQUEST",
        "TERRAIN_REPORT",
        "BATTERY_STATUS",
        "GIMBAL_DEVICE_ATTITUDE_STATUS",
        "OPTICAL_FLOW",
        "MAG_CAL_REPORT",
        "MAG_CAL_PROGRESS",
        "EKF_STATUS_REPORT",
        "VIBRATION",
        "ESC_TELEMETRY_1_TO_4",
        "AOA_SSA",
        "EXTENDED_SYS_STATE",
    },
}
STREAM_OF = {name: sid for sid, names in STREAMS.items() for name in names}
DEFAULT_RADIO_HZ = 2.0  # until the GCS asks for something else


def sim_only(msg) -> bool:
    """Simulator-only traffic: never forwarded to the radio or shown to the IDS."""
    t = msg.get_type()
    return t == "SIMSTATE" or (t in ("PARAM_VALUE", "PARAM_SET") and msg.param_id.startswith("SIM_"))


class Router:
    def __init__(
        self,
        a: str,
        b: str,
        ids_port: int = 15600,
        onboard: bool = False,
        fc_rate_hz: int = 50,
        sign_key: bytes | None = None,
        commit_key: bytes | None = None,
        imu_rate_hz: int = 0,
    ):
        self.a = mavutil.mavlink_connection(a, source_system=ROUTER_SYSID, source_component=ROUTER_COMPID)
        self.b = mavutil.mavlink_connection(b, source_system=ROUTER_SYSID, source_component=ROUTER_COMPID)
        self.ids = ("127.0.0.1", ids_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.onboard = onboard
        self.fc_rate_hz = fc_rate_hz
        self.imu_rate_hz = imu_rate_hz
        self.signer = Signer(sign_key) if sign_key else None  # ground agent only
        self.commit = CommitTx(commit_key) if commit_key else None  # onboard agent only
        self._gcs_seq: int | None = None
        self._uplink: deque = deque()  # (t, received, missing) of GCS frames, last 30 s (onboard)
        self._link_mav = mav2.MAVLink(None, srcSystem=ROUTER_SYSID, srcComponent=ROUTER_COMPID)
        self.radio_hz: dict[str, float] = {}  # per message type, set by GCS requests
        self._last_tx: dict[str, float] = {}
        self.stats = {"a_to_b": Counter(), "b_to_a": Counter(), "dropped": Counter(), "bytes_to_b": 0}
        self._stop = threading.Event()

    # -- shaping (onboard only) ------------------------------------------------------
    def _allow_downlink(self, name: str, now: float) -> bool:
        if name not in STREAM_OF and name not in self.radio_hz:
            return True
        hz = self.radio_hz.get(name, DEFAULT_RADIO_HZ)
        if hz <= 0:
            return False
        if now - self._last_tx.get(name, -1e9) < 0.9 / hz:  # 10 % slack for jitter
            return False
        self._last_tx[name] = now
        return True

    def _intercept_uplink(self, msg) -> bool:
        """Handle GCS stream-rate requests locally. Returns True if consumed."""
        t = msg.get_type()
        if t == "REQUEST_DATA_STREAM":
            hz = msg.req_message_rate if msg.start_stop else 0
            ids = STREAMS if msg.req_stream_id == MAV.MAV_DATA_STREAM_ALL else [msg.req_stream_id]
            for sid in ids:
                for name in STREAMS.get(sid, ()):
                    self.radio_hz[name] = hz
            return True
        if t == "COMMAND_LONG" and msg.command == MAV.MAV_CMD_SET_MESSAGE_INTERVAL:
            entry = MAV.mavlink_map.get(int(msg.param1))
            if entry is not None:
                us = msg.param2
                self.radio_hz[entry.msgname] = 0 if us < 0 else (DEFAULT_RADIO_HZ if us == 0 else 1e6 / us)
            ack = MAV.MAVLink_command_ack_message(
                msg.command, MAV.MAV_RESULT_ACCEPTED if entry else MAV.MAV_RESULT_FAILED
            )
            buf = ack.pack(self.b.mav)
            self.b.mav.seq = (self.b.mav.seq + 1) % 256
            self.b.write(buf)
            if self.commit:
                self.commit.add(buf, ack)  # our own downlink frames are committed too
            return True
        return False

    def request_fc_streams(self):
        ts, tc = self.a.target_system or 1, self.a.target_component or 1
        self.a.mav.request_data_stream_send(ts, tc, MAV.MAV_DATA_STREAM_ALL, self.fc_rate_hz, 1)
        if self.imu_rate_hz:  # the IDS integrates IMU: as fast as the FC link sustains (less aliasing)
            self.a.mav.command_long_send(
                ts,
                tc,
                MAV.MAV_CMD_SET_MESSAGE_INTERVAL,
                0,
                MAV.MAVLINK_MSG_ID_RAW_IMU,
                1e6 / self.imu_rate_hz,
                0,
                0,
                0,
                0,
                0,
            )

    # -- forwarding --------------------------------------------------------------------
    def _mirror(self, direction: bytes, buf: bytes):
        try:
            self.sock.sendto(direction + buf, self.ids)
        except OSError:
            pass  # IDS down or buffer full: forwarding must not depend on it

    def uplink_loss(self, now: float, span_s: float = 30.0) -> float | None:
        """Loss of the GCS's frames on the uplink, from its sequence gaps (onboard)."""
        while self._uplink and now - self._uplink[0][0] > span_s:
            self._uplink.popleft()
        got = sum(x[1] for x in self._uplink)
        miss = sum(x[2] for x in self._uplink)
        return miss / (got + miss) if got >= 10 else None

    def _pump(self, src, dst, direction: bytes, key: str):
        while not self._stop.is_set():
            if self.commit and direction == b"D":
                frames = self.commit.flush(time.monotonic())
                if frames:  # one link report per commitment window
                    p = self.uplink_loss(time.monotonic())
                    report = mav2.MAVLink_gr_link_message(255 if p is None else round(100 * p))
                    frames.append(report.pack(self._link_mav))
                    self._link_mav.seq = (self._link_mav.seq + 1) % 256
                for frame in frames:
                    dst.write(frame)
                    self.stats["bytes_to_b"] += len(frame)
            msg = src.recv_match(blocking=True, timeout=0.1)
            if msg is None:
                continue
            name = msg.get_type()
            buf = msg.get_msgbuf()
            if name == "BAD_DATA":
                self._mirror(direction, bytes(buf))  # protocol layer counts malformed frames
                self.stats["dropped"]["BAD_DATA"] += 1
                continue
            if self.onboard and direction == b"D" and sim_only(msg):
                self.stats["dropped"][name] += 1
                continue
            self._mirror(direction, bytes(buf))
            if self.onboard and direction == b"U" and msg.get_srcSystem() == 255 and msg.get_srcComponent() == 190:
                seq = msg.get_seq()
                gap = 0 if self._gcs_seq is None else (seq - self._gcs_seq - 1) % 256
                if gap < 128:
                    self._uplink.append((time.monotonic(), 1, gap))
                self._gcs_seq = seq
            if self.signer and direction == b"D" and name == "GR_LINK":
                self.signer.uplink_loss = None if msg.uplink_loss == 255 else msg.uplink_loss / 100
            if self.onboard and direction == b"U" and (name.startswith("GR_") or self._intercept_uplink(msg)):
                self.stats["dropped"][name] += 1  # IDS traffic and rate requests end here
                continue
            if self.onboard and direction == b"D" and not self._allow_downlink(name, time.monotonic()):
                continue
            if not self.onboard and direction == b"D" and name.startswith("GR_"):
                continue  # commitments end at the ground agent
            dst.write(buf)
            if self.commit and direction == b"D":
                self.commit.add(bytes(buf), msg)
            if self.signer and direction == b"U" and is_command(msg):
                for sig in self.signer.sign(bytes(buf), msg):
                    dst.write(sig)
            self.stats[key][name] += 1
            if key == "a_to_b":
                self.stats["bytes_to_b"] += len(buf)

    def start(self):
        if self.onboard:
            self.a.wait_heartbeat(timeout=60)
            self.request_fc_streams()
        for args in ((self.a, self.b, b"D", "a_to_b"), (self.b, self.a, b"U", "b_to_a")):
            threading.Thread(target=self._pump, args=args, daemon=True).start()
        return self

    def stop(self):
        self._stop.set()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--a", required=True, help="aircraft side (FC onboard, radio on ground)")
    ap.add_argument("--b", required=True, help="GCS side (radio onboard, GCS on ground)")
    ap.add_argument("--ids-port", type=int, default=15600)
    ap.add_argument("--onboard", action="store_true")
    ap.add_argument("--fc-rate", type=int, default=50)
    ap.add_argument("--imu-rate", type=int, default=0, help="onboard: RAW_IMU rate to request from the FC, Hz")
    ap.add_argument("--sign-key", type=Path, help="ground agent: file with the hex Ed25519 private seed")
    ap.add_argument("--commit-key", type=Path, help="onboard agent: file with the hex Ed25519 private seed")
    args = ap.parse_args()

    def load(p):
        return bytes.fromhex(p.read_text().strip()) if p else None

    r = Router(
        args.a,
        args.b,
        args.ids_port,
        args.onboard,
        args.fc_rate,
        load(args.sign_key),
        load(args.commit_key),
        args.imu_rate,
    ).start()
    while True:
        time.sleep(10)
        if r.onboard:
            r.request_fc_streams()  # FC forgets stream rates on reboot


if __name__ == "__main__":
    main()
