"""Evidence events and alert episodes (plan F7).

Detectors emit ``EvidenceEvent``s. Fusion turns persisted evidence into ``Alert``s.
``EpisodeTracker`` groups alerts of the same class into episodes: one episode = one
alarm for metric purposes (spec §5). Further alerts of that class merge into the open
episode until no alert of that class has arrived for ``clear_after_s``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass(frozen=True)
class EvidenceEvent:
    t: float
    uav_id: int
    source: str  # detector name, e.g. "cpce.R1", "protocol.seq", "commit_rx"
    evidence_type: str  # e.g. "gnss_velocity_residual", "tag_altered"
    score: float  # normalised, larger = more anomalous
    severity: Severity = Severity.INFO
    class_hint: Optional[str] = None  # attack class this evidence points at, if any
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Alert:
    t: float
    uav_id: int
    attack_class: str
    confidence: float
    severity: Severity
    evidence: tuple = ()  # EvidenceEvents that triggered it


@dataclass
class Episode:
    episode_id: int
    uav_id: int
    attack_class: str
    t_start: float
    t_last: float
    alerts: list = field(default_factory=list)
    t_end: Optional[float] = None

    @property
    def open(self) -> bool:
        return self.t_end is None


class EpisodeTracker:
    def __init__(self, clear_after_s: float = 10.0):
        self.clear_after_s = clear_after_s
        self.episodes: list[Episode] = []
        self._open: dict[tuple[int, str], Episode] = {}

    def update(self, alert: Alert) -> tuple[Episode, bool]:
        """Record an alert. Returns (episode, is_new_episode)."""
        self.close_idle(alert.t)
        key = (alert.uav_id, alert.attack_class)
        ep = self._open.get(key)
        if ep is not None:
            ep.t_last = alert.t
            ep.alerts.append(alert)
            return ep, False
        ep = Episode(len(self.episodes), alert.uav_id, alert.attack_class, alert.t, alert.t, [alert])
        self.episodes.append(ep)
        self._open[key] = ep
        return ep, True

    def close_idle(self, now: float) -> list[Episode]:
        """Close episodes with no alert for clear_after_s. Returns the newly closed ones."""
        closed = []
        for key, ep in list(self._open.items()):
            if now - ep.t_last >= self.clear_after_s:
                ep.t_end = ep.t_last
                del self._open[key]
                closed.append(ep)
        return closed

    def open_episodes(self) -> list[Episode]:
        return list(self._open.values())
