"""IDS process (one per agent): router mirror -> Samples -> detectors -> fusion -> episodes -> log.

Detectors are plain objects with
    observe(msg, samples, direction, t) -> list[EvidenceEvent]
    tick(t) -> list[EvidenceEvent]            (optional; time-driven checks, e.g. timeouts)
``msg`` is the raw pymavlink message (protocol/commitment layers need seq, ids, bytes);
``samples`` are the platform-independent Samples the adapter made from it; ``direction`` is
"D" (from the aircraft side) or "U" (from the GCS side).

Runs live on the router's mirror port, or replays the tlogs a scenario run recorded, so
the same traffic can be evaluated many times offline.

    python -m gaganrakshak.ids --replay results/raw/<run>/onboard --log evidence.jsonl
"""

from __future__ import annotations

import argparse
import heapq
import socket
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pymavlink import mavutil
from pymavlink.dialects.v20 import ardupilotmega as mav2

from .adapter import ArduPilotAdapter
from .evidence import Alert, EpisodeTracker, EvidenceEvent, Severity
from .evidence_log import EvidenceLog


class PassThroughFusion:
    """Minimal fusion: evidence of MEDIUM+ severity with a class hint becomes an alert.
    Replaced by CUSUM + evidence templates in the physics/fusion track."""

    def update(self, events: list[EvidenceEvent], t: float) -> list[Alert]:
        return [
            Alert(
                t=e.t,
                uav_id=e.uav_id,
                attack_class=e.class_hint,
                confidence=min(1.0, e.score),
                severity=e.severity,
                evidence=(e,),
            )
            for e in events
            if e.class_hint and e.severity >= Severity.MEDIUM
        ]


class Ids:
    def __init__(
        self,
        detectors: list,
        fusion=None,
        log: EvidenceLog | None = None,
        uav_id: int = 1,
        clear_after_s: float = 10.0,
    ):
        self.adapter = ArduPilotAdapter(uav_id)
        self.detectors = detectors
        self.fusion = fusion or PassThroughFusion()
        self.tracker = EpisodeTracker(clear_after_s)
        self.log = log or EvidenceLog()
        self.alerts: list[Alert] = []

    def feed(self, msg, direction: str, t: float) -> list[Alert]:
        samples = self.adapter.convert(msg, t)
        events = [e for d in self.detectors for e in d.observe(msg, samples, direction, t)]
        return self._decide(events, t)

    def tick(self, t: float) -> list[Alert]:
        events = [e for d in self.detectors if hasattr(d, "tick") for e in d.tick(t)]
        return self._decide(events, t)

    def _decide(self, events: list[EvidenceEvent], t: float) -> list[Alert]:
        for ep in self.tracker.close_idle(t):
            self.log.append(
                {
                    "t": t,
                    "kind": "episode_closed",
                    "episode": ep.episode_id,
                    "class": ep.attack_class,
                    "t_start": ep.t_start,
                    "t_end": ep.t_end,
                }
            )
        alerts = self.fusion.update(events, t) if events else []
        for a in alerts:
            ep, new = self.tracker.update(a)
            self.alerts.append(a)
            if new:
                self.log.append(
                    {
                        "t": a.t,
                        "kind": "episode_opened",
                        "episode": ep.episode_id,
                        "class": a.attack_class,
                        "severity": int(a.severity),
                        "confidence": a.confidence,
                        "evidence": [
                            {"source": e.source, "type": e.evidence_type, "score": e.score} for e in a.evidence
                        ],
                    }
                )
        return alerts


def replay_tlogs(prefix: Path) -> Iterable[tuple[float, str, Any]]:  # Any: pymavlink messages are untyped
    """(time, direction, msg) from <prefix>_D.tlog and <prefix>_U.tlog, merged in time order."""

    def read(direction):
        path = Path(f"{prefix}_{direction}.tlog")
        if not path.exists():
            return
        log = mavutil.mavlink_connection(str(path), robust_parsing=True)
        while (m := log.recv_msg()) is not None:
            yield m._timestamp, direction, m

    return heapq.merge(read("D"), read("U"), key=lambda x: x[0])


def run_replay(ids: Ids, prefix: Path, tick_s: float = 0.1) -> Ids:
    next_tick = None
    for t, direction, msg in replay_tlogs(prefix):
        if next_tick is None:
            next_tick = t
        if t - next_tick > 3600:
            raise ValueError(f"{prefix}: time jumps {t - next_tick:.0f} s; corrupt tlog?")
        while t >= next_tick:
            ids.tick(next_tick)
            next_tick += tick_s
        ids.feed(msg, direction, t)
    return ids


def run_live(ids: Ids, port: int, tick_s: float = 0.1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    sock.settimeout(tick_s)
    next_tick = time.monotonic()
    while True:
        try:
            f = sock.recv(4096)
            parser = mav2.MAVLink(None)
            parser.robust_parsing = True
            msg = parser.parse_char(f[1:])
            if msg is not None:
                ids.feed(msg, f[:1].decode(), time.monotonic())
        except TimeoutError:
            pass
        if time.monotonic() >= next_tick:
            ids.tick(time.monotonic())
            next_tick += tick_s


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--replay", type=Path, help="tlog prefix, e.g. results/raw/<run>/onboard")
    src.add_argument("--port", type=int, help="router mirror port (live)")
    ap.add_argument("--log", type=Path, default=None, help="evidence log (JSONL)")
    a = ap.parse_args()
    ids = Ids(detectors=[], log=EvidenceLog(a.log))
    if a.replay:
        run_replay(ids, a.replay)
        print(f"{len(ids.tracker.episodes)} episodes; adapter unknown types: {dict(ids.adapter.stats['unknown'])}")
    else:
        run_live(ids, a.port)


if __name__ == "__main__":
    main()
