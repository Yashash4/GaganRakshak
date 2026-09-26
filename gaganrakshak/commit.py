"""Signed downlink commitments: onboard ``CommitTx`` (in the onboard router), ground
``CommitRx`` (an IDS detector in the ground agent).

Onboard: every security-relevant frame forwarded to the radio is listed as
(seq, msgid, first 4 bytes of SHA-256(frame)); once per window the list is sent as signed
GR_COMMIT chunks (Ed25519, one signature per chunk, ~1 chunk per window at GCS rates).

Ground: the radio link delivers in order, so a frame's commitment is the first GR_COMMIT
window sent after it. If the last window seen before a frame was w-1 and the next is w,
the frame must be listed in w:
- listed, same hash       -> match
- listed, different hash  -> ``tag_altered``      [telemetry_manipulation]
- not listed              -> ``tag_unexpected``   (injected)  [telemetry_manipulation]
- a window was lost between -> unverified (link statistic, never an alarm)
Commitment-level evidence:
- ``commit_bad_signature``   chunk signature does not verify   [telemetry_manipulation]
- ``selective_commit_loss``  commitments lost far more often than ordinary frames — random
                             radio loss hits both alike   [telemetry_manipulation]
- ``commit_timeout``         telemetry keeps flowing but no commitment for ``timeout_s``
Listed frames that never arrive are counted as missing (radio loss) for the link monitor.
"""

from __future__ import annotations

import hashlib
import threading
from collections import deque

from pymavlink.dialects.v20 import ardupilotmega as mav2

from . import crypto
from .evidence import EvidenceEvent, Severity

# Downlink messages an attacker would alter to mislead the operator (all msgid < 256).
# Derived duplicates (LOCAL_POSITION_NED, MISSION_CURRENT) are left out to save radio bandwidth.
RELEVANT = {"HEARTBEAT", "SYS_STATUS", "GPS_RAW_INT", "GLOBAL_POSITION_INT", "ATTITUDE", "VFR_HUD",
            "STATUSTEXT", "COMMAND_ACK", "PARAM_VALUE", "EKF_STATUS_REPORT", "HOME_POSITION",
            "BATTERY_STATUS", "MISSION_ITEM_INT", "MISSION_COUNT"}
ENTRY = 6
PER_CHUNK = 30  # 4+3+64+180 = 251-byte payload, one signature for a typical window
CLASS = "telemetry_manipulation"


def tag(frame: bytes) -> bytes:
    return hashlib.sha256(frame).digest()[:4]


def _signed_bytes(window_id, chunk, n_chunks, count, entries: bytes) -> bytes:
    return window_id.to_bytes(4, "big") + bytes([chunk, n_chunks, count]) + entries


class CommitTx:
    def __init__(self, private_seed: bytes, window_s: float = 1.0, sysid: int = 1, compid: int = 191):
        self.seed = private_seed
        self.window_s = window_s
        self.window_id = 0
        self._entries: list[bytes] = []
        self._t_close = None
        self._lock = threading.Lock()  # both router threads may forward downlink frames
        self._mav = mav2.MAVLink(None, srcSystem=sysid, srcComponent=compid)

    def add(self, frame: bytes, msg) -> None:
        if msg.get_type() in RELEVANT:
            with self._lock:
                self._entries.append(bytes([msg.get_seq(), msg.get_msgId()]) + tag(frame))

    def flush(self, now: float) -> list[bytes]:
        """GR_COMMIT frames for the window if it is due, else []."""
        with self._lock:
            if self._t_close is None:
                self._t_close = now + self.window_s
            if now < self._t_close:
                return []
            self._t_close += self.window_s
            entries, self._entries = self._entries, []
            wid = self.window_id
            self.window_id += 1
        chunks = [entries[i:i + PER_CHUNK] for i in range(0, len(entries), PER_CHUNK)] or [[]]
        out = []
        for i, c in enumerate(chunks):
            body = b"".join(c)
            sig = crypto.sign(_signed_bytes(wid, i, len(chunks), len(c), body), self.seed)
            m = mav2.MAVLink_gr_commit_message(wid, i, len(chunks), len(c), sig, body.ljust(PER_CHUNK * ENTRY, b"\0"))
            out.append(m.pack(self._mav))
            self._mav.seq = (self._mav.seq + 1) % 256
        return out


class CommitRx:
    def __init__(self, public_key: bytes, uav_id: int = 1, timeout_s: float = 5.0,
                 loss_history: int = 60, selective_margin: float = 0.15, selective_min: int = 5):
        self.pub = public_key
        self.uav_id = uav_id
        self.timeout_s = timeout_s
        self.selective_margin = selective_margin
        self.selective_min = selective_min
        self.last_window = None  # highest window id seen (any chunk)
        self._pending = []  # [t, seq, msgid, tag, name, prev_window]
        self._chunks: dict[int, dict] = {}  # window -> {"n": n_chunks, "got": {chunk: {(seq,msgid): tag}}}
        self._history = deque(maxlen=loss_history)  # per window: (lost_window, listed, missing)
        self._t_last_commit = None
        self._recent_frames = deque()  # arrival times of relevant frames within timeout_s
        self._selective = self._timed_out = False
        self._t_congested = None  # last RADIO_STATUS with a nearly full radio buffer
        self.congestion_hold_s = 10.0
        self.stats = {"match": 0, "altered": 0, "unexpected": 0, "unverified": 0, "missing": 0,
                      "windows": 0, "windows_lost": 0}

    def _ev(self, t, kind, sev, **meta):
        return EvidenceEvent(t, self.uav_id, "commit_rx", kind, 1.0, sev, CLASS, meta)

    def _loss_ev(self, t, kind, **meta):
        """Commitment loss while the radio is congested is explained by the congestion: a full
        buffer drops large frames (commitments) first. Then it corroborates DoS instead."""
        congested = self._t_congested is not None and t - self._t_congested < self.congestion_hold_s
        return EvidenceEvent(t, self.uav_id, "commit_rx", kind, 1.0, Severity.MEDIUM,
                             "dos" if congested else CLASS, {**meta, "congested": congested})

    def observe(self, msg, samples, direction, t):
        if direction != "D":
            return []
        name = msg.get_type()
        if name == "GR_COMMIT":
            return self._commit(msg, t)
        if name == "RADIO_STATUS" and msg.txbuf < 50:
            self._t_congested = t
        if name in RELEVANT:
            self._pending.append([t, msg.get_seq(), msg.get_msgId(), tag(bytes(msg.get_msgbuf())), name,
                                  self.last_window])
            self._recent_frames.append(t)
        return []

    def _commit(self, m, t):
        entries = bytes(m.entries)[:m.count * ENTRY]
        if not crypto.verify(_signed_bytes(m.window_id, m.chunk, m.n_chunks, m.count, entries),
                             bytes(m.signature), self.pub):
            return [self._ev(t, "commit_bad_signature", Severity.HIGH, window=m.window_id)]
        self._t_last_commit, self._timed_out = t, False
        w = m.window_id
        # (seq, msgid) -> tags. Not unique: at FC rates the 8-bit seq wraps several times per window.
        listed = {}
        for i in range(0, len(entries), ENTRY):
            listed.setdefault((entries[i], entries[i + 1]), []).append(entries[i + 2:i + 6])
        self._chunks.setdefault(w, {"n": m.n_chunks, "got": {}})["got"][m.chunk] = listed
        out = []
        if self.last_window is None or w > self.last_window:
            # windows before w are final now
            for old in sorted(k for k in self._chunks if k < w):
                out += self._resolve(old, t, final=True)
            if self.last_window is not None:
                for lost in range(self.last_window + 1, w):
                    self._history.append((True, 0, 0))
                    self.stats["windows_lost"] += 1
            self.last_window = w
        c = self._chunks[w]
        if len(c["got"]) == c["n"]:
            out += self._resolve(w, t, final=True)
        return out + self._selective_check(t)

    def _resolve(self, w, t, final):
        c = self._chunks.pop(w)
        complete = len(c["got"]) == c["n"]
        listed = {}
        for part in c["got"].values():
            for k, tags in part.items():
                listed.setdefault(k, []).extend(tags)
        n_listed = sum(len(tags) for tags in listed.values())
        out, keep = [], []
        for f in self._pending:
            ft, seq, msgid, h, name, prev = f
            if prev is not None and prev >= w:
                keep.append(f)  # belongs to a later window
                continue
            k = (seq, msgid)
            if k in listed:
                if h in listed[k]:
                    listed[k].remove(h)
                    self.stats["match"] += 1
                else:
                    self.stats["altered"] += 1
                    out.append(self._ev(t, "tag_altered", Severity.HIGH, msg=name, seq=seq, window=w))
            elif prev is not None and prev == w - 1 and complete:
                self.stats["unexpected"] += 1
                out.append(self._ev(t, "tag_unexpected", Severity.HIGH, msg=name, seq=seq, window=w))
            else:
                self.stats["unverified"] += 1  # first frames, or a window/chunk lost on the radio
        self._pending = keep
        missing = sum(len(tags) for tags in listed.values())
        self.stats["missing"] += missing
        self.stats["windows"] += 1
        self._history.append((False, n_listed, missing))
        return out

    def recent_loss(self, windows: int = 10) -> tuple[int, int, int]:
        """(frames listed, listed frames missing, windows lost) over the last ``windows`` windows."""
        h = list(self._history)[-windows:]
        return sum(n for _, n, _ in h), sum(m for _, _, m in h), sum(1 for lost, _, _ in h if lost)

    def _selective_check(self, t):
        lost_w = sum(1 for lost, _, _ in self._history if lost)
        listed = sum(n for _, n, _ in self._history)
        missing = sum(m for _, _, m in self._history)
        p_frame = missing / listed if listed else 0.0
        p_commit = lost_w / len(self._history) if self._history else 0.0
        selective = lost_w >= self.selective_min and p_commit > p_frame + self.selective_margin
        out = []
        if selective and not self._selective:
            out.append(self._loss_ev(t, "selective_commit_loss",
                                     commit_loss=round(p_commit, 3), frame_loss=round(p_frame, 3)))
        self._selective = selective
        return out

    def tick(self, t, min_rate_hz: float = 5.0):
        """Telemetry kept flowing for the whole ``timeout_s`` but no commitment came. An outage
        (jamming, fade) stops both and is the link monitor's business, not this one's."""
        while self._recent_frames and t - self._recent_frames[0] > self.timeout_s:
            self._recent_frames.popleft()
        flowing = len(self._recent_frames) >= min_rate_hz * self.timeout_s
        if (self._t_last_commit is not None and not self._timed_out and flowing
                and t - self._t_last_commit > self.timeout_s):
            self._timed_out = True
            return [self._loss_ev(t, "commit_timeout", silent_s=round(t - self._t_last_commit, 1))]
        return []
