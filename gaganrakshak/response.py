"""Command -> response consistency (ground agent). Independent of the signature layer.

The ground agent sits between the GCS and the radio, so it sees every command the GCS really
sent, and it sees what the autopilot reports back. A flight-mode change the GCS did not ask
for, and that the autopilot did not announce as a failsafe, was commanded by someone else.

Evidence:
- ``uncommanded_mode_change``  the autopilot's mode changed with no matching GCS command in
  the last ``window_s`` and no failsafe/mode-change notice   [command_injection, HIGH]
"""

from __future__ import annotations

from pymavlink import mavutil

from .evidence import EvidenceEvent, Severity

MAV = mavutil.mavlink
COPTER_MODES = mavutil.mode_mapping_acm  # ArduCopter custom mode numbers -> names
MODE_OF_COMMAND = {  # COMMAND_LONG commands that change the mode by themselves
    MAV.MAV_CMD_NAV_LAND: "LAND",
    MAV.MAV_CMD_NAV_RETURN_TO_LAUNCH: "RTL",
}
FAILSAFE_WORDS = ("failsafe", "fence", "ekf", "gps glitch", "battery", "radio", "crash")


class ResponseMonitor:
    def __init__(self, uav_id: int = 1, window_s: float = 5.0, notice_s: float = 3.0):
        self.uav_id = uav_id
        self.window_s, self.notice_s = window_s, notice_s
        self.mode: str | None = None
        self._expected: list[tuple[float, str]] = []  # (t, mode) requested by the GCS
        self._t_notice = -1e9

    def _requested_mode(self, msg) -> str | None:
        t = msg.get_type()
        if t == "SET_MODE":
            return COPTER_MODES.get(msg.custom_mode)
        if t in ("COMMAND_LONG", "COMMAND_INT"):
            if msg.command == MAV.MAV_CMD_DO_SET_MODE:
                return COPTER_MODES.get(int(msg.param2))
            return MODE_OF_COMMAND.get(msg.command)
        return None

    def observe(self, msg, samples, direction, t):
        name = msg.get_type()
        if direction == "U":  # at the ground agent: what the GCS really sent
            mode = self._requested_mode(msg)
            if mode:
                self._expected.append((t, mode))
            return []
        if name == "STATUSTEXT" and msg.get_srcSystem() == 1:
            if any(w in msg.text.lower() for w in FAILSAFE_WORDS):
                self._t_notice = t
            return []
        if name != "HEARTBEAT" or msg.get_srcSystem() != 1:
            return []
        mode = mavutil.mode_string_v10(msg)
        previous, self.mode = self.mode, mode
        if previous is None or mode == previous:
            return []
        self._expected = [(te, m) for te, m in self._expected if t - te <= self.window_s]
        if any(m == mode for _, m in self._expected) or t - self._t_notice <= self.notice_s:
            return []
        return [
            EvidenceEvent(
                t,
                self.uav_id,
                "response",
                "uncommanded_mode_change",
                1.0,
                Severity.HIGH,
                "command_injection",
                {"from": previous, "to": mode},
            )
        ]
