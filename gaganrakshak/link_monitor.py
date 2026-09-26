"""Ground link monitor (IDS detector in the ground agent): DoS / jamming evidence.

Measured downlink frame loss comes from the commitments (frames listed by the aircraft vs
frames that arrived) — exact per-frame loss, which the thinned sequence numbers cannot give.
It is compared with the loss expected at the current distance from the radio's link budget
(logistic in distance, configured from the radio's range; ``d50_m`` = 50 % loss distance).

Evidence (class ``dos``):
- ``excess_loss``       loss over the last ``window`` commitment windows exceeds expected + margin
- ``telemetry_gap``     no FC heartbeat for ``gap_s`` (outage, jamming burst)
- ``radio_congestion``  air-side radio buffer below ``txbuf_min`` % for ``congestion_s`` (flood)
Metadata always carries distance, expected and observed loss so fusion can weigh benign fades.
"""

from __future__ import annotations

import math

from .evidence import EvidenceEvent, Severity


class LinkMonitor:
    def __init__(self, commit_rx, uav_id: int = 1, d50_m: float | None = None, scale_m: float = 100.0,
                 base_loss: float = 0.02, margin: float = 0.2, window: int = 10, min_frames: int = 20,
                 gap_s: float = 3.0, txbuf_min: int = 20, congestion_s: float = 3.0):
        self.rx = commit_rx
        self.uav_id = uav_id
        self.d50_m, self.scale_m, self.base_loss, self.margin = d50_m, scale_m, base_loss, margin
        self.window, self.min_frames = window, min_frames
        self.gap_s, self.txbuf_min, self.congestion_s = gap_s, txbuf_min, congestion_s
        self.home = None
        self.distance_m = 0.0
        self._t_hb = None
        self._in = {"loss": False, "gap": False, "congestion": False}
        self._t_congested = None
        self.last = {}

    def expected_loss(self) -> float:
        p = self.base_loss
        if self.d50_m is not None:
            pd = 1 / (1 + math.exp(-(self.distance_m - self.d50_m) / self.scale_m))
            p = 1 - (1 - p) * (1 - pd)
        return p

    def _ev(self, t, kind, sev, **meta):
        meta.update(distance_m=round(self.distance_m, 1), expected_loss=round(self.expected_loss(), 3))
        return EvidenceEvent(t, self.uav_id, "link_monitor", kind, meta.get("score", 1.0), sev, "dos", meta)

    def _onset(self, key, active, t, make):
        """One event per onset of a condition; re-armed when it clears."""
        out = [make()] if active and not self._in[key] else []
        self._in[key] = active
        return out

    def observe(self, msg, samples, direction, t):
        if direction != "D":
            return []
        name = msg.get_type()
        if name == "HEARTBEAT" and msg.get_srcSystem() == 1:
            self._t_hb = t
        elif name == "GLOBAL_POSITION_INT" and msg.get_srcSystem() == 1 and (msg.lat or msg.lon):
            lat, lon = msg.lat / 1e7, msg.lon / 1e7
            if self.home is None:
                self.home = (lat, lon)
            dn = math.radians(lat - self.home[0]) * 6371000
            de = math.radians(lon - self.home[1]) * 6371000 * math.cos(math.radians(lat))
            self.distance_m = math.hypot(dn, de)
        elif name == "RADIO_STATUS":
            if msg.txbuf < self.txbuf_min:
                self._t_congested = self._t_congested if self._t_congested is not None else t
            else:
                self._t_congested = None
        elif name == "GR_COMMIT":
            listed, missing, lost = self.rx.recent_loss(self.window)
            if listed >= self.min_frames:
                observed = missing / listed
                self.last = {"observed": observed, "expected": self.expected_loss()}
                return self._onset("loss", observed > self.expected_loss() + self.margin, t,
                                   lambda: self._ev(t, "excess_loss", Severity.MEDIUM,
                                                    observed_loss=round(observed, 3), windows_lost=lost))
        return []

    def tick(self, t):
        out = []
        if self._t_hb is not None:
            silent = t - self._t_hb
            out += self._onset("gap", silent > self.gap_s, t,
                               lambda: self._ev(t, "telemetry_gap", Severity.MEDIUM, silent_s=round(silent, 1)))
        congested = self._t_congested is not None and t - self._t_congested >= self.congestion_s
        out += self._onset("congestion", congested, t,
                           lambda: self._ev(t, "radio_congestion", Severity.MEDIUM))
        return out
