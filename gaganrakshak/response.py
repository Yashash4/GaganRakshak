"""Command -> response consistency (ground agent). Independent of the signature layer.

The ground agent sits between the GCS and the radio, so it sees every command the GCS really
sent, and it sees what the autopilot reports back. A flight-mode change the GCS did not ask
for, and that the autopilot did not announce as a failsafe, was commanded by someone else.

A failsafe notice (STATUSTEXT) excuses a mode change only if it is trustworthy: the downlink
commitments verified the notice frame as the autopilot's own, or the telemetry shows the
condition it names (battery low, EKF test ratios near the gate, a telemetry outage for a
radio/GCS failsafe, a fence breach). Otherwise an attacker could inject a fake notice next to
an injected mode change. With commitments unavailable (``rx`` None) only corroboration counts.

Evidence:
- ``uncommanded_mode_change``  the autopilot's mode changed with no matching GCS command in
  the last ``window_s`` and no trustworthy failsafe notice   [command_injection, HIGH]
- ``uncommanded_target_change``  the autopilot's position target moved > TARGET_MOVE_M with no
  GCS position request and no mode change in ``window_s``   [command_injection, HIGH]
- ``uncommanded_servo_output``   an auxiliary output (servo 5-16) changed > SERVO_STEP_US with no
  GCS servo command or RC override in ``window_s``   [command_injection, HIGH]
- ``uncommanded_mission_change`` the current mission item changed outside AUTO, or in AUTO to an
  item the uploaded mission cannot reach next (DO_JUMP-aware), with no GCS set-current   [command_injection, HIGH]
  (clean flights: no unrequested target move, aux output change or mission change in 112 flights,
  7.4 h, so the thresholds only clear measurement resolution)
- ``excused_mode_change``      an unrequested mode change excused by a notice, with why (verified
  frame, or the corroborating condition). Some corroborators can be induced by an attacker
  (a GNSS spoof raises EKF ratios, jamming causes an outage); the autopilot failing over is then
  genuine, the attack itself raises its own alarm, and this record keeps the chain   [INFO]
"""

from __future__ import annotations

import math
from collections import deque

from pymavlink import mavutil

from .evidence import EvidenceEvent, Severity

MAV = mavutil.mavlink
COPTER_MODES = mavutil.mode_mapping_acm  # ArduCopter custom mode numbers -> names
MODE_OF_COMMAND = {  # COMMAND_LONG commands that change the mode by themselves
    MAV.MAV_CMD_NAV_LAND: "LAND",
    MAV.MAV_CMD_NAV_RETURN_TO_LAUNCH: "RTL",
}
FAILSAFE_WORDS = ("failsafe", "fence", "ekf", "gps glitch", "battery", "radio", "crash")
BATTERY_LOW_PCT = 25  # remaining capacity at or below which a battery failsafe is plausible
EKF_RATIO_NEAR_GATE = 0.8  # innovation test ratio (1 = ArduPilot's gate)
OUTAGE_S = 3.0  # telemetry silence that corroborates a radio / GCS failsafe
CORROBORATION_S = 15.0  # how far back the corroborating condition may lie
TARGET_MOVE_M = 1.0
SERVO_STEP_US = 50
AUX_SERVOS = range(5, 17)  # 1-4 drive the quad's motors
MAV_CMD_DO_JUMP = 177
POSITION_REQUESTS = {
    "SET_POSITION_TARGET_LOCAL_NED",
    "SET_POSITION_TARGET_GLOBAL_INT",
    "MISSION_ITEM",
    "MISSION_ITEM_INT",
}
POSITION_COMMANDS = {MAV.MAV_CMD_NAV_TAKEOFF, MAV.MAV_CMD_DO_REPOSITION, MAV.MAV_CMD_NAV_WAYPOINT, MAV.MAV_CMD_NAV_LAND}
SERVO_COMMANDS = {MAV.MAV_CMD_DO_SET_SERVO, MAV.MAV_CMD_DO_REPEAT_SERVO}


class ResponseMonitor:
    def __init__(self, uav_id: int = 1, window_s: float = 5.0, notice_s: float = 3.0, rx=None, verdict_s: float = 5.0):
        self.uav_id = uav_id
        self.window_s, self.notice_s = window_s, notice_s
        self.rx = rx  # CommitRx of the same agent: verdicts on received frames
        self.verdict_s = verdict_s  # how long to wait for a notice's commitment verdict
        self.mode: str | None = None
        self._expected: list[tuple[float, str]] = []  # (t, mode) requested by the GCS
        self._notices: deque = deque(maxlen=50)  # (t, seq, msgid, text)
        self._held: list[dict] = []  # mode changes waiting for their notices' verdicts
        self._t_battery_low = self._t_ekf_high = self._t_fence = self._t_outage = -1e9
        self._t_last_fc: float | None = None
        self._t_pos_req = self._t_servo_req = self._t_mission_req = self._t_mode_change = -1e9
        self._target: tuple[float, float, float] | None = None
        self._aux: list[int] | None = None
        self._mission_item: int | None = None
        self._mission: dict[int, tuple[int, float]] = {}  # uploaded items: seq -> (command, param1)

    def _requested_mode(self, msg) -> str | None:
        t = msg.get_type()
        if t == "SET_MODE":
            return COPTER_MODES.get(msg.custom_mode)
        if t in ("COMMAND_LONG", "COMMAND_INT"):
            if msg.command == MAV.MAV_CMD_DO_SET_MODE:
                return COPTER_MODES.get(int(msg.param2))
            return MODE_OF_COMMAND.get(msg.command)
        return None

    def _telemetry(self, msg, name, t):
        if self._t_last_fc is not None and t - self._t_last_fc >= OUTAGE_S:
            self._t_outage = t
        self._t_last_fc = t
        if name == "SYS_STATUS" and 0 <= msg.battery_remaining <= BATTERY_LOW_PCT:
            self._t_battery_low = t
        elif name == "EKF_STATUS_REPORT":
            ratios = (msg.velocity_variance, msg.pos_horiz_variance, msg.pos_vert_variance, msg.compass_variance)
            if max(ratios) >= EKF_RATIO_NEAR_GATE:
                self._t_ekf_high = t
        elif name == "FENCE_STATUS" and msg.breach_status:
            self._t_fence = t

    def _corroboration(self, text: str, t: float) -> str | None:
        """The telemetry condition that corroborates the notice, or None."""
        for words, t_cond, cond in (
            (("battery",), self._t_battery_low, "battery_low"),
            (("fence",), self._t_fence, "fence_breach"),
            (("ekf", "gps"), self._t_ekf_high, "ekf_ratio_near_gate"),
            (("radio", "gcs"), self._t_outage, "telemetry_outage"),
        ):
            if any(w in text for w in words):
                return cond if t - t_cond <= CORROBORATION_S else None
        return None  # e.g. "crash": only a verified notice excuses it

    def _judge(self, held: dict, t: float, final: bool) -> list[EvidenceEvent] | None:
        """[] once excused; [evidence] once no notice can excuse it; None while undecided."""
        waiting = False
        for tn, seq, msgid, text in held["notices"]:
            v = self.rx.verdict(tn, seq, msgid) if self.rx is not None else "unverified"
            why = "verified" if v == "match" else self._corroboration(text, t)
            if why:
                meta = {"from": held["from"], "to": held["to"], "notice": text, "excused_by": why, "notice_verdict": v}
                return [
                    EvidenceEvent(
                        held["t"], self.uav_id, "response", "excused_mode_change", 0.0, Severity.INFO, None, meta
                    )
                ]
            waiting |= v is None
        if waiting and not final:
            return None
        return [
            EvidenceEvent(
                held["t"],
                self.uav_id,
                "response",
                "uncommanded_mode_change",
                1.0,
                Severity.HIGH,
                "command_injection",
                {"from": held["from"], "to": held["to"], "notices": [n[3] for n in held["notices"]]},
            )
        ]

    def _settle(self, t: float) -> list[EvidenceEvent]:
        out: list[EvidenceEvent] = []
        keep: list[dict] = []
        for held in self._held:
            ev = self._judge(held, t, final=t - held["t"] >= self.verdict_s)
            if ev is None:
                keep.append(held)
            else:
                out += ev
        self._held = keep
        return out

    def _uplink(self, msg, name, t):
        if name in POSITION_REQUESTS:
            self._t_pos_req = t
        if name in ("MISSION_ITEM", "MISSION_ITEM_INT"):
            self._mission[msg.seq] = (msg.command, msg.param1)
        elif name == "MISSION_COUNT":
            self._mission = {}
        elif name == "MISSION_SET_CURRENT":
            self._t_mission_req = t
        elif name == "RC_CHANNELS_OVERRIDE":
            self._t_servo_req = t
        elif name in ("COMMAND_LONG", "COMMAND_INT"):
            if msg.command in POSITION_COMMANDS:
                self._t_pos_req = t
            elif msg.command in SERVO_COMMANDS:
                self._t_servo_req = t
            elif msg.command == MAV.MAV_CMD_DO_SET_MISSION_CURRENT:
                self._t_mission_req = t

    def _reachable(self, cur: int) -> set[int]:
        """Items the uploaded mission can go to next from ``cur``: the next one(s), following
        DO_JUMP items (a jump that has run out continues after itself)."""
        out, todo = set(), [cur + 1]
        while todo:
            s = todo.pop()
            if s in out:
                continue
            out.add(s)
            cmd, p1 = self._mission.get(s, (None, 0.0))
            if cmd == MAV_CMD_DO_JUMP:
                todo += [int(p1), s + 1]
        return out

    def _ev(self, t, kind, **meta):
        return [EvidenceEvent(t, self.uav_id, "response", kind, 1.0, Severity.HIGH, "command_injection", meta)]

    def _state(self, msg, name, t) -> list[EvidenceEvent]:
        """Commanded-state changes the autopilot reports: position target, aux outputs, mission item."""
        quiet = lambda t_req: t - t_req > self.window_s  # noqa: E731
        if name == "POSITION_TARGET_GLOBAL_INT":
            tgt = (msg.lat_int / 1e7, msg.lon_int / 1e7, float(msg.alt))
            prev, self._target = self._target, tgt
            if prev is None:
                return []
            dn = (tgt[0] - prev[0]) * 111320.0
            de = (tgt[1] - prev[1]) * 111320.0 * math.cos(math.radians(tgt[0]))
            move = math.sqrt(dn * dn + de * de + (tgt[2] - prev[2]) ** 2)
            if move > TARGET_MOVE_M and quiet(self._t_pos_req) and quiet(self._t_mode_change):
                return self._ev(t, "uncommanded_target_change", move_m=round(move, 1))
        elif name == "SERVO_OUTPUT_RAW":
            aux = [getattr(msg, f"servo{i}_raw", 0) for i in AUX_SERVOS]
            prev_aux, self._aux = self._aux, aux
            if prev_aux is not None and quiet(self._t_servo_req):
                pairs = zip(AUX_SERVOS, aux, prev_aux, strict=True)
                steps = [(i, abs(a - b)) for i, a, b in pairs if abs(a - b) > SERVO_STEP_US]
                if steps:
                    return self._ev(t, "uncommanded_servo_output", servo=steps[0][0], step_us=steps[0][1])
        elif name == "MISSION_CURRENT":
            cur, prev_item = msg.seq, self._mission_item
            self._mission_item = cur
            if prev_item is None or cur == prev_item or not quiet(self._t_mission_req):
                return []
            if self.mode != "AUTO" or cur not in self._reachable(prev_item):
                return self._ev(t, "uncommanded_mission_change", from_item=prev_item, to_item=cur, mode=self.mode)
        return []

    def tick(self, t):
        return self._settle(t)

    def observe(self, msg, samples, direction, t):
        name = msg.get_type()
        if direction == "U":  # at the ground agent: what the GCS really sent
            mode = self._requested_mode(msg)
            if mode:
                self._expected.append((t, mode))
            self._uplink(msg, name, t)
            return []
        if msg.get_srcSystem() != 1:
            return []
        self._telemetry(msg, name, t)
        if name == "STATUSTEXT":
            text = msg.text.lower()
            if any(w in text for w in FAILSAFE_WORDS):
                self._notices.append((t, msg.get_seq(), msg.get_msgId(), text))
            return self._settle(t)
        if name != "HEARTBEAT":
            return self._state(msg, name, t) + self._settle(t)
        mode = mavutil.mode_string_v10(msg)
        previous, self.mode = self.mode, mode
        if previous is None or mode == previous:
            return self._settle(t)
        self._t_mode_change = t
        self._expected = [(te, m) for te, m in self._expected if t - te <= self.window_s]
        if any(m == mode for _, m in self._expected):
            return self._settle(t)
        notices = [n for n in self._notices if t - n[0] <= self.notice_s]
        self._held.append({"t": t, "from": previous, "to": mode, "notices": notices})
        return self._settle(t)
