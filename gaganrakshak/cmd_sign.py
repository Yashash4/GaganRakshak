"""Signed uplink commands.

Ground agent (``Signer``, inside the ground router): after forwarding each command frame from
the GCS it sends a GR_CMD_SIG = Ed25519 over (monotonic counter || exact command frame bytes).
The signature is sent twice so that one radio loss does not leave a command unsigned.

Onboard agent (``CmdVerifier``, an IDS detector): pairs each uplink command with its
signature. Evidence (class ``command_injection`` unless noted):
- ``unsigned_command``   no valid signature arrived within ``wait_s`` (injected, or both
                         signature copies lost on the radio — the second is rare by design)
- ``bad_signature``      signature present but does not verify (altered command or forged sig)
- ``replayed_command``   valid signature, counter not newer than the last accepted  [replay]
Alert-only: commands are always forwarded; blocking is a deployment option, not the default.
"""

from __future__ import annotations

import time

from pymavlink.dialects.v20 import ardupilotmega as mav2

from . import crypto
from .adapter import COMMAND_MSGS
from .evidence import EvidenceEvent, Severity

GROUND_SYSID, GROUND_COMPID = 255, 191  # the ground agent speaks as part of the GCS system
COPIES = 2


def _signed_bytes(counter: int, frame: bytes) -> bytes:
    return counter.to_bytes(8, "big") + frame


def is_command(msg) -> bool:
    return msg.get_type() in COMMAND_MSGS


class Signer:
    def __init__(self, private_seed: bytes):
        self.seed = private_seed
        self.counter = time.time_ns() // 1000  # monotonic across restarts of the ground agent
        self._mav = mav2.MAVLink(None, srcSystem=GROUND_SYSID, srcComponent=GROUND_COMPID)

    def sign(self, frame: bytes, msg) -> list[bytes]:
        self.counter += 1
        sig = crypto.sign(_signed_bytes(self.counter, frame), self.seed)
        m = mav2.MAVLink_gr_cmd_sig_message(self.counter, msg.get_msgId(), msg.get_srcSystem(),
                                            msg.get_srcComponent(), msg.get_seq(), sig)
        out = []
        for _ in range(COPIES):
            out.append(m.pack(self._mav))
            self._mav.seq = (self._mav.seq + 1) % 256
        return out


class CmdVerifier:
    def __init__(self, public_key: bytes, uav_id: int = 1, wait_s: float = 0.5):
        self.pub = public_key
        self.uav_id = uav_id
        self.wait_s = wait_s
        self.last_counter = -1
        self._cmds = {}  # key -> (t, frame bytes, name)
        self._sigs = {}  # key -> list of GR_CMD_SIG
        self.verified = 0
        self.outcome = {}  # command key -> "verified" | "bad_signature" | "replayed" | "unsigned"

    @staticmethod
    def _key(sysid, compid, seq, msgid):
        return sysid, compid, seq, msgid

    @classmethod
    def key_of(cls, msg):
        return cls._key(msg.get_srcSystem(), msg.get_srcComponent(), msg.get_seq(), msg.get_msgId())

    def _set(self, k, result):
        self.outcome[k] = result
        if len(self.outcome) > 4096:  # bounded: consumers read outcomes within seconds
            del self.outcome[next(iter(self.outcome))]

    def _ev(self, t, kind, sev, cls, **meta):
        return EvidenceEvent(t, self.uav_id, "cmd_sign", kind, 1.0, sev, cls, meta)

    def observe(self, msg, samples, direction, t):
        if direction != "U":
            return []
        if msg.get_type() == "GR_CMD_SIG":
            k = self._key(msg.cmd_sysid, msg.cmd_compid, msg.cmd_seq, msg.cmd_msgid)
            self._sigs.setdefault(k, []).append(msg)
        elif is_command(msg):
            k = self.key_of(msg)
            self._cmds[k] = (t, bytes(msg.get_msgbuf()), msg.get_type())
        else:
            return []
        return self._match(t)

    def _match(self, t):
        out = []
        for k in [k for k in self._cmds if k in self._sigs]:
            t_cmd, frame, name = self._cmds.pop(k)
            sigs = self._sigs.pop(k)
            ok = [s for s in sigs if crypto.verify(_signed_bytes(s.counter, frame), bytes(s.signature), self.pub)]
            self._set(k, "bad_signature" if not ok else "replayed" if ok[0].counter <= self.last_counter
                      else "verified")
            if not ok:
                out.append(self._ev(t, "bad_signature", Severity.HIGH, "command_injection", command=name))
            elif ok[0].counter <= self.last_counter:
                out.append(self._ev(t, "replayed_command", Severity.HIGH, "replay", command=name,
                                    counter=ok[0].counter, last=self.last_counter))
            else:
                self.last_counter = ok[0].counter
                self.verified += 1
        return out

    def tick(self, t):
        out = []
        for k, (t_cmd, _, name) in list(self._cmds.items()):
            if t - t_cmd > self.wait_s:
                del self._cmds[k]
                self._set(k, "unsigned")
                out.append(self._ev(t, "unsigned_command", Severity.MEDIUM, "command_injection",
                                    command=name, sysid=k[0]))
        for k in list(self._sigs):  # signatures whose command was lost on the radio
            if k not in self._cmds:
                del self._sigs[k]
        return out
