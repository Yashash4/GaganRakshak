"""Signed uplink commands.

Ground agent (``Signer``, inside the ground router): after forwarding each command frame from
the GCS it sends a GR_CMD_SIG = Ed25519 over (monotonic counter || exact command frame bytes).
The signature is sent k times, k chosen from the uplink loss the onboard agent measures and reports
(GR_LINK_SIGNED, signed with the onboard commitment key) so that losing every copy is rarer than 1e-3;
without a valid report in the last LINK_STALE_S the ground agent sends COPIES_MAX.

Onboard agent (``CmdVerifier``, an IDS detector): pairs each uplink command with its
signature. Evidence (class ``command_injection`` unless noted):
- ``unsigned_command``   no valid signature arrived within ``wait_s`` (injected, or both
                         signature copies lost on the radio). When the uplink loss measured from
                         the GCS's own sequence gaps makes losing both copies likely (p² > alpha),
                         it is reported as LOW ``dos`` corroboration instead.
- ``bad_signature``      signature present but does not verify (altered command or forged sig)
- ``replayed_command``   valid signature, counter not newer than the last accepted  [replay]
Alert-only: commands are always forwarded; blocking is a deployment option, not the default.
"""

from __future__ import annotations

import math
import time
from collections import deque
from typing import Any

from pymavlink.dialects.v20 import ardupilotmega as mav2

from . import crypto
from .adapter import COMMAND_MSGS
from .evidence import EvidenceEvent, Severity

GROUND_SYSID, GROUND_COMPID = 255, 191  # the ground agent speaks as part of the GCS system
COPIES_ALPHA = 1e-3  # accepted probability that every signature copy of a command is lost
COPIES_MAX = 16
COPIES_MIN = 4  # commands are rare: extra copies cost almost nothing (all 4 lost at 40 % loss: 2.6 %)
COPIES_DEFAULT = 6  # before the first uplink-loss report (covers up to ~31 % loss)


def copies_for(uplink_loss: float | None) -> int:
    """Signature copies so that all are lost with probability <= COPIES_ALPHA, given the uplink
    loss: k = ceil(ln alpha / ln p), at least COPIES_MIN, at most COPIES_MAX."""
    if uplink_loss is None:
        return max(COPIES_MIN, COPIES_DEFAULT)
    if uplink_loss <= 0:
        return COPIES_MIN
    if uplink_loss >= 1:
        return COPIES_MAX
    return max(COPIES_MIN, min(COPIES_MAX, math.ceil(math.log(COPIES_ALPHA) / math.log(uplink_loss))))


def loss_upper(received: int, missing: int, z: float = 1.645) -> float:
    """One-sided 95 % Wilson upper bound of a loss rate: few samples (the GCS sends ~1 frame/s)
    cannot show that loss is low, and signature copies must not be sized from a lucky zero."""
    n = received + missing
    if n == 0:
        return 1.0
    p = missing / n
    centre = p + z * z / (2 * n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return min(1.0, (centre + half) / (1 + z * z / n))


def _signed_bytes(counter: int, frame: bytes) -> bytes:
    return counter.to_bytes(8, "big") + frame


LINK_STALE_S = 10.0  # without a valid GR_LINK_SIGNED this recent, the ground agent sends COPIES_MAX


def _link_bytes(counter: int, uplink_loss: int) -> bytes:
    return b"GR_LINK" + counter.to_bytes(8, "big") + bytes([uplink_loss])  # domain tag: the key also signs GR_COMMIT


def link_report(counter: int, uplink_loss: float | None, seed: bytes):
    """Onboard agent's GR_LINK_SIGNED (uplink loss in percent, 255 = unknown)."""
    pct = 255 if uplink_loss is None else round(100 * uplink_loss)
    return mav2.MAVLink_gr_link_signed_message(counter, pct, crypto.sign(_link_bytes(counter, pct), seed))


class LinkReports:
    """Ground agent: accepts GR_LINK_SIGNED only if it verifies with the onboard commitment key and its
    counter is newer than the last accepted one; sizes signature copies from the latest."""

    def __init__(self, public_key: bytes | None):
        self.pub = public_key
        self.counter = -1
        self.t: float | None = None
        self.uplink_loss: float | None = None

    def accept(self, msg, now: float) -> bool:
        if self.pub is None or msg.counter <= self.counter:
            return False
        if not crypto.verify(_link_bytes(msg.counter, msg.uplink_loss), bytes(msg.signature), self.pub):
            return False
        self.counter, self.t = msg.counter, now
        self.uplink_loss = None if msg.uplink_loss == 255 else msg.uplink_loss / 100
        return True

    def copies(self, now: float, downlink_loss: float = 0.0) -> int:
        """From the worse of the reported uplink loss (an upper bound) and the downlink loss the
        ground measures itself: the downlink is dense and sees a fade at once; more copies only help."""
        if self.t is None or now - self.t > LINK_STALE_S:
            return COPIES_MAX  # no trustworthy loss report: assume the worst
        if self.uplink_loss is None:
            return copies_for(None)
        return copies_for(max(self.uplink_loss, downlink_loss))


def is_command(msg) -> bool:
    return msg.get_type() in COMMAND_MSGS


class Signer:
    def __init__(self, private_seed: bytes):
        self.seed = private_seed
        self.counter = time.time_ns() // 1000  # monotonic across restarts of the ground agent
        self._mav = mav2.MAVLink(None, srcSystem=GROUND_SYSID, srcComponent=GROUND_COMPID)
        self.uplink_loss: float | None = None  # used when sign() is not given a copy count

    def sign(self, frame: bytes, msg, copies: int | None = None) -> list[bytes]:
        """``copies`` signature frames (default: from ``uplink_loss``)."""
        self.counter += 1
        sig = crypto.sign(_signed_bytes(self.counter, frame), self.seed)
        m = mav2.MAVLink_gr_cmd_sig_message(
            self.counter, msg.get_msgId(), msg.get_srcSystem(), msg.get_srcComponent(), msg.get_seq(), sig
        )
        out = []
        for _ in range(copies_for(self.uplink_loss) if copies is None else copies):
            out.append(m.pack(self._mav))
            self._mav.seq = (self._mav.seq + 1) % 256
        return out


class CmdVerifier:
    def __init__(self, public_key: bytes, uav_id: int = 1, wait_s: float = 0.5):
        self.pub = public_key
        self.uav_id = uav_id
        self.wait_s = wait_s
        self.last_counter = -1
        # Several frames can share a key (an injected frame reusing the GCS's next seq, then the genuine
        # one): every frame is kept and judged on its own bytes, never replaced by a later one.
        self._cmds: dict[tuple[int, int, int, int], list[tuple[float, bytes, str]]] = {}  # key -> [(t, frame, name)]
        self._sigs: dict[tuple[int, int, int, int], list[tuple[float, Any]]] = {}  # key -> [(t, GR_CMD_SIG)]
        self.verified = 0
        self._gcs_seq: int | None = None
        self._uplink: deque[tuple[float, int, int]] = (
            deque()
        )  # (t, frames received, frames missing) from the GCS's own seq gaps
        self.alpha = 1e-3
        self.outcome: dict[
            tuple[int, int, int, int], str
        ] = {}  # command key -> "verified" | "bad_signature" | "replayed" | "unsigned"

    @staticmethod
    def _key(sysid, compid, seq, msgid):
        return sysid, compid, seq, msgid

    @classmethod
    def key_of(cls, msg):
        return cls._key(msg.get_srcSystem(), msg.get_srcComponent(), msg.get_seq(), msg.get_msgId())

    RANK = {"verified": 0, "replayed": 1, "unsigned": 2, "bad_signature": 3}

    def _set(self, k, result):
        # frames sharing a key: the key's outcome is the worst of their verdicts
        if k in self.outcome and self.RANK[self.outcome[k]] >= self.RANK[result]:
            return
        self.outcome[k] = result
        if len(self.outcome) > 4096:  # bounded: consumers read outcomes within seconds
            del self.outcome[next(iter(self.outcome))]

    def _ev(self, t, kind, sev, cls, **meta):
        return EvidenceEvent(t, self.uav_id, "cmd_sign", kind, 1.0, sev, cls, meta)

    def uplink_loss(self, t, span_s: float = 30.0) -> float:
        while self._uplink and t - self._uplink[0][0] > span_s:
            self._uplink.popleft()
        got = sum(x[1] for x in self._uplink)
        miss = sum(x[2] for x in self._uplink)
        return loss_upper(got, miss)

    def observe(self, msg, samples, direction, t):
        if direction != "U":
            return []
        if msg.get_srcSystem() == 255 and msg.get_srcComponent() == 190:
            seq = msg.get_seq()
            gap = 0 if self._gcs_seq is None else (seq - self._gcs_seq - 1) % 256
            if gap < 128:  # larger = reordering/duplicate, the protocol layer's business
                self._uplink.append((t, 1, gap))
            self._gcs_seq = seq
        if msg.get_type() == "GR_CMD_SIG":
            k = self._key(msg.cmd_sysid, msg.cmd_compid, msg.cmd_seq, msg.cmd_msgid)
            self._sigs.setdefault(k, []).append((t, msg))
        elif is_command(msg):
            self._cmds.setdefault(self.key_of(msg), []).append((t, bytes(msg.get_msgbuf()), msg.get_type()))
        else:
            return []
        return self._match(t)

    def _match(self, t):
        """Pair each waiting frame with a signature over its exact bytes; unmatched frames wait
        (their signature may still come) and are judged in tick()."""
        out = []
        for k in [k for k in self._cmds if k in self._sigs]:
            waiting = []
            for t_cmd, frame, name in self._cmds[k]:
                sigs = [s for _, s in self._sigs[k]]
                ok = [s for s in sigs if crypto.verify(_signed_bytes(s.counter, frame), bytes(s.signature), self.pub)]
                if ok:
                    out += self._judge(k, t, name, ok[0])
                else:
                    waiting.append((t_cmd, frame, name))
            if waiting:
                self._cmds[k] = waiting
            else:
                del self._cmds[k]
        return out

    def _judge(self, k, t, name, sig) -> list[EvidenceEvent]:
        """A frame whose exact bytes the signature covers: verified, or replayed (stale counter)."""
        if sig.counter <= self.last_counter:
            self._set(k, "replayed")
            meta = {"command": name, "counter": sig.counter, "last": self.last_counter}
            return [self._ev(t, "replayed_command", Severity.HIGH, "replay", **meta)]
        self._set(k, "verified")
        self.last_counter = sig.counter
        self.verified += 1
        return []

    def tick(self, t):
        out = []
        for k, frames in list(self._cmds.items()):
            due = [f for f in frames if t - f[0] > self.wait_s]
            if not due:
                continue
            rest = [f for f in frames if t - f[0] <= self.wait_s]
            if rest:
                self._cmds[k] = rest
            else:
                del self._cmds[k]
            for _t_cmd, _, name in due:
                if self._sigs.get(k):  # signed commands carried this key, but none signed this frame
                    self._set(k, "bad_signature")
                    out.append(self._ev(t, "bad_signature", Severity.HIGH, "command_injection", command=name))
                    continue
                self._set(k, "unsigned")
                # Never downgraded by loss: an attacker can cause uplink loss (jamming) exactly when
                # injecting. The loss context goes to the operator as metadata only.
                p = self.uplink_loss(t)
                kk = copies_for(p)
                meta = {"command": name, "sysid": k[0], "uplink_loss_upper": round(p, 3), "copies_expected": kk}
                meta["all_copies_lost_probability"] = round(p**kk, 5)
                out.append(self._ev(t, "unsigned_command", Severity.MEDIUM, "command_injection", **meta))
        for k in list(self._sigs):  # keep signatures one wait period, for frames sharing their key
            self._sigs[k] = [(ts, sg) for ts, sg in self._sigs[k] if t - ts <= 2 * self.wait_s]
            if not self._sigs[k] and k not in self._cmds:
                del self._sigs[k]
        return out
