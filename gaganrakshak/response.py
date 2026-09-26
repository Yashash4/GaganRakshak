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
"""

from __future__ import annotations

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

    def _corroborated(self, text: str, t: float) -> bool:
        recent = lambda t_cond: t - t_cond <= CORROBORATION_S  # noqa: E731
        if "battery" in text:
            return recent(self._t_battery_low)
        if "fence" in text:
            return recent(self._t_fence)
        if "ekf" in text or "gps" in text:
            return recent(self._t_ekf_high)
        if "radio" in text or "gcs" in text:
            return recent(self._t_outage)
        return False  # e.g. "crash": only a verified notice excuses it

    def _judge(self, held: dict, t: float, final: bool) -> list[EvidenceEvent] | None:
        """[] once excused; [evidence] once no notice can excuse it; None while undecided."""
        waiting = False
        for tn, seq, msgid, text in held["notices"]:
            v = self.rx.verdict(tn, seq, msgid) if self.rx is not None else "unverified"
            if v == "match" or self._corroborated(text, t):
                return []
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

    def tick(self, t):
        return self._settle(t)

    def observe(self, msg, samples, direction, t):
        name = msg.get_type()
        if direction == "U":  # at the ground agent: what the GCS really sent
            mode = self._requested_mode(msg)
            if mode:
                self._expected.append((t, mode))
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
            return self._settle(t)
        mode = mavutil.mode_string_v10(msg)
        previous, self.mode = self.mode, mode
        if previous is None or mode == previous:
            return self._settle(t)
        self._expected = [(te, m) for te, m in self._expected if t - te <= self.window_s]
        if any(m == mode for _, m in self._expected):
            return self._settle(t)
        notices = [n for n in self._notices if t - n[0] <= self.notice_s]
        self._held.append({"t": t, "from": previous, "to": mode, "notices": notices})
        return self._settle(t)
