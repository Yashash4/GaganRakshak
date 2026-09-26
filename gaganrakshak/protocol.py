"""Protocol-layer detector (MAVLink anomalies), runs in both agents.

Evidence it emits (class hint in brackets):
- ``seq_duplicate``   a sender's sequence number repeats within its recent window.
                      Radio loss only creates gaps; a repeat means a second sender using the
                      same ids, or replayed frames. [mavlink_anomaly]
- ``unknown_source``  a system id that should not be on this path in this direction. [mavlink_anomaly]
- ``malformed``       bytes that are not a valid MAVLink frame (bad CRC / framing). [mavlink_anomaly]
- ``uplink_flood``    more uplink messages per second than any GCS sends. [dos]
- ``unsafe_command``  disarm / reboot / calibration / flight termination while airborne,
                      not verified as a signed GCS command (cmd_sign). [command_injection]
                      A verified one is the operator's: logged as INFO ``operator_unsafe_command``.
                      Only the onboard agent judges this: the ground agent's uplink comes from
                      its own GCS, and injection happens on the radio link after it.
Sequence gaps are counted (link statistics) but are not attack evidence on their own.

Duplicate checks need the sender's full stream. The onboard router thins the downlink to the
GCS-requested rates, so on the ground the FC's 8-bit sequence wraps between forwarded frames
and repeats by coincidence; there, injected telemetry is caught by the signed commitments
instead. ``for_agent`` picks the right setting.
"""

from __future__ import annotations

from collections import defaultdict, deque

from pymavlink import mavutil

from .evidence import EvidenceEvent, Severity

MAV = mavutil.mavlink
UNSAFE_IN_FLIGHT = {
    MAV.MAV_CMD_COMPONENT_ARM_DISARM,  # only when disarming (param1 == 0)
    MAV.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN,
    MAV.MAV_CMD_PREFLIGHT_CALIBRATION,
    MAV.MAV_CMD_DO_FLIGHTTERMINATION,
}
FC_SYSID, GCS_SYSID, RADIO_SYSID = 1, 255, 51


AIRBORNE_THROTTLE_PCT = 10  # below this a multicopter is not flying (clean flights: >= 19 % airborne, 0 landed)


class ProtocolDetector:
    def __init__(
        self,
        uav_id: int = 1,
        allowed: dict | None = None,
        dup_window: int = 32,
        uplink_max_per_s: int = 50,
        airborne_m: float = 1.0,
        seq_dirs=("D", "U"),
        verifier=None,
        check_unsafe: bool = True,
        max_wait_s: float = 60.0,
    ):
        self.uav_id = uav_id
        self.verifier = verifier  # cmd_sign.CmdVerifier: decides whether an unsafe command is the operator's
        self.check_unsafe = check_unsafe
        self.max_wait_s = max_wait_s  # safety bound only: the verifier concludes every command it sees
        self._unsafe: list[
            tuple[float, tuple[int, int, int, int], int, int]
        ] = []  # (t, command key, command, sysid) awaiting the signature verdict
        self.seq_dirs = set(seq_dirs)
        self.allowed = allowed or {"D": {FC_SYSID, RADIO_SYSID}, "U": {GCS_SYSID}}
        self.dup_window = dup_window
        self.uplink_max_per_s = uplink_max_per_s
        self.airborne_m = airborne_m
        self._recent: defaultdict[tuple[str, int, int], deque[int]] = defaultdict(
            lambda: deque(maxlen=dup_window)
        )  # (dir, sys, comp) -> seqs
        self._last_seq: dict[tuple[str, int, int], int] = {}
        self.gaps: defaultdict[tuple[str, int, int], int] = defaultdict(
            int
        )  # (dir, sys, comp) -> frames missing (link statistics)
        self._uplink: deque[float] = deque()  # timestamps of uplink messages in the last second
        self._flooding = False
        self.airborne = False
        self._above_home = False
        self._lift = True  # until the first VFR_HUD: height alone decides, as before
        self._t_alt = -1e9  # airborne state older than 2 s is unknown (e.g. lossy ground downlink)

    def _ev(self, t, kind, score, sev, cls, **meta):
        return EvidenceEvent(t, self.uav_id, "protocol", kind, score, sev, cls, meta)

    def observe(self, msg, samples, direction, t):
        name = msg.get_type()
        if name == "BAD_DATA":
            return [
                self._ev(
                    t,
                    "malformed",
                    1.0,
                    Severity.MEDIUM,
                    "mavlink_anomaly",
                    direction=direction,
                    reason=getattr(msg, "reason", ""),
                )
            ]
        out = []
        sysid, compid, seq = msg.get_srcSystem(), msg.get_srcComponent(), msg.get_seq()
        # Airborne = above home AND the autopilot is producing lift. Height above home alone fails
        # where the landing site's terrain differs from home's; on clean flights airborne throttle
        # never fell below 19 % and was 0 on the ground.
        if name == "GLOBAL_POSITION_INT" and sysid == FC_SYSID:
            self._above_home = msg.relative_alt / 1000.0 > self.airborne_m
            self.airborne = self._above_home and self._lift
            self._t_alt = t
        elif name == "VFR_HUD" and sysid == FC_SYSID:
            self._lift = msg.throttle > AIRBORNE_THROTTLE_PCT
            self.airborne = self._above_home and self._lift

        if sysid not in self.allowed.get(direction, ()):
            out.append(
                self._ev(
                    t,
                    "unknown_source",
                    1.0,
                    Severity.HIGH,
                    "mavlink_anomaly",
                    direction=direction,
                    sysid=sysid,
                    compid=compid,
                    msg=name,
                )
            )

        key = (direction, sysid, compid)
        recent = self._recent[key]
        if seq in recent and direction in self.seq_dirs:
            out.append(
                self._ev(
                    t,
                    "seq_duplicate",
                    1.0,
                    Severity.MEDIUM,
                    "mavlink_anomaly",
                    direction=direction,
                    sysid=sysid,
                    compid=compid,
                    seq=seq,
                    msg=name,
                )
            )
        elif key in self._last_seq:
            self.gaps[key] += (seq - self._last_seq[key] - 1) % 256
        recent.append(seq)
        self._last_seq[key] = seq

        if direction == "U":
            self._uplink.append(t)
            while self._uplink and t - self._uplink[0] > 1.0:
                self._uplink.popleft()
            flooding = len(self._uplink) > self.uplink_max_per_s
            if flooding and not self._flooding:  # one event per flood onset, re-armed when it ends
                out.append(
                    self._ev(
                        t,
                        "uplink_flood",
                        len(self._uplink) / self.uplink_max_per_s,
                        Severity.HIGH,
                        "dos",
                        rate=len(self._uplink),
                    )
                )
            self._flooding = flooding

        if (
            self.check_unsafe
            and name in ("COMMAND_LONG", "COMMAND_INT")
            and msg.command in UNSAFE_IN_FLIGHT
            and self.airborne
            and t - self._t_alt < 2.0
            and not (msg.command == MAV.MAV_CMD_COMPONENT_ARM_DISARM and msg.param1 == 1)
        ):
            cmd_key = (sysid, compid, seq, msg.get_msgId())
            if self.verifier is None:
                out.append(
                    self._ev(
                        t,
                        "unsafe_command",
                        1.0,
                        Severity.HIGH,
                        "command_injection",
                        direction=direction,
                        command=int(msg.command),
                        sysid=sysid,
                    )
                )
            else:
                self._unsafe.append((t, cmd_key, int(msg.command), sysid))
        return out

    def tick(self, t):
        """Unsafe commands are judged once the signature check has a final outcome for that
        command (no fixed delay: on a slow link the verdict takes longer)."""
        out, keep = [], []
        for item in self._unsafe:
            t0, key, command, sysid = item
            verdict = self.verifier.outcome.get(key)
            if verdict is None and t - t0 < self.max_wait_s:
                keep.append(item)
            elif verdict == "verified":
                out.append(
                    self._ev(t, "operator_unsafe_command", 0.0, Severity.INFO, None, command=command, sysid=sysid)
                )
            else:
                out.append(
                    self._ev(
                        t,
                        "unsafe_command",
                        1.0,
                        Severity.HIGH,
                        "command_injection",
                        command=command,
                        sysid=sysid,
                        signature=verdict or "no verdict",
                        uplink_loss=round(self.verifier.uplink_loss(t), 3),
                    )
                )
        self._unsafe = keep
        return out


def for_agent(agent: str, **kw) -> ProtocolDetector:
    """onboard: full streams both ways; unsafe commands judged with the signature verdict.
    ground: downlink thinned by the onboard router; uplink is its own GCS (no unsafe check)."""
    if agent == "onboard":
        return ProtocolDetector(seq_dirs=("D", "U"), **kw)
    return ProtocolDetector(seq_dirs=("U",), check_unsafe=False, **kw)
