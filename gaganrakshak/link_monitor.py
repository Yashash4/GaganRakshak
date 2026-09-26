"""Ground link monitor (IDS detector in the ground agent): DoS / jamming evidence.

Measured downlink frame loss comes from the commitments (frames listed by the aircraft vs
frames that arrived) — exact per-frame loss, which the thinned sequence numbers cannot give.
It is compared with the loss that is normal at the current distance. That expectation is
**learned from clean calibration flights** (``LossCurve``): per distance bin, the upper band
median + k·MAD of the observed loss, made non-decreasing with distance, with k the smallest
value that meets the false-alarm budget on the calibration flights. The monitor has no radio
model of its own.

Evidence (class ``dos``):
- ``excess_loss``       loss over the last ``window`` commitment windows above the learned band
- ``telemetry_gap``     FC heartbeat silence above the band learned for this distance
                        (outage, jamming burst)
- ``radio_congestion``  air-side radio buffer below ``txbuf_min`` % for ``congestion_s`` (flood)
Metadata carries distance, expected and observed loss so fusion can weigh benign fades.

    python -m gaganrakshak.link_monitor results/raw/calib/* --out results/calibration/link_curves.json
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path

from .evidence import EvidenceEvent, Severity


class BandCurve:
    """Upper band of a link statistic vs distance, learned from clean flights."""

    def __init__(self, bin_m: float, upper: list[float], meta: dict | None = None):
        self.bin_m, self.upper, self.meta = bin_m, upper, meta or {}

    def upper_at(self, distance_m: float) -> float:
        """Beyond the calibrated range the last (largest) band applies."""
        return self.upper[min(int(distance_m // self.bin_m), len(self.upper) - 1)]

    @classmethod
    def fit(cls, samples: list[tuple[float, float]], k: float, bin_m: float = 50.0, floor: float = 0.05,
            cap: float = 1.0, min_per_bin: int = 5) -> "BandCurve":
        """samples = (distance, value). ``floor`` is the smallest band (loss: a single lost burst
        in a 10-window span is several percent; heartbeat silence: 3 s = three missed 1 Hz beats)."""
        n_bins = int(max(d for d, _ in samples) // bin_m) + 1
        upper, prev = [], floor
        for b in range(n_bins):
            xs = [x for d, x in samples if b * bin_m <= d < (b + 1) * bin_m]
            if len(xs) >= min_per_bin:
                med = statistics.median(xs)
                mad = statistics.median(abs(x - med) for x in xs)
                prev = max(prev, min(cap, med + k * 1.4826 * mad + floor))
            upper.append(prev)  # non-decreasing; sparse bins inherit the band below
        return cls(bin_m, upper)

    def to_dict(self) -> dict:
        return {"bin_m": self.bin_m, "upper": self.upper, "meta": self.meta}

    @classmethod
    def from_dict(cls, d: dict) -> "BandCurve":
        return cls(d["bin_m"], d["upper"], d.get("meta"))


LossCurve = BandCurve  # loss-vs-distance band


def save_curves(path: Path, curves: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({k: c.to_dict() for k, c in curves.items()}, indent=1))


def load_curves(path: Path) -> dict:
    return {k: BandCurve.from_dict(d) for k, d in json.loads(Path(path).read_text()).items()}


class LinkMonitor:
    def __init__(self, commit_rx, uav_id: int = 1, curves: dict | None = None, window: int = 10,
                 min_frames: int = 100, gap_s: float = 3.0, txbuf_min: int = 20, congestion_s: float = 3.0):
        self.rx = commit_rx
        self.uav_id = uav_id
        curves = curves or {}  # none: record samples only (calibration); no loss/gap evidence
        self.curve, self.gap_curve = curves.get("loss"), curves.get("gap")
        self.window, self.min_frames = window, min_frames
        self.gap_s, self.txbuf_min, self.congestion_s = gap_s, txbuf_min, congestion_s
        self.home = None
        self.distance_m = 0.0
        self.samples: list[tuple[float, float, float]] = []  # (t, distance, windowed loss)
        self.gap_samples: list[tuple[float, float, float]] = []  # (t, distance, heartbeat silence)
        self._t_hb = None
        self._in = {"loss": False, "gap": False, "congestion": False}
        self._t_congested = None

    def _ev(self, t, kind, **meta):
        meta["distance_m"] = round(self.distance_m, 1)
        if self.curve:
            meta["expected_loss_upper"] = round(self.curve.upper_at(self.distance_m), 3)
        return EvidenceEvent(t, self.uav_id, "link_monitor", kind, 1.0, Severity.MEDIUM, "dos", meta)

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
            if self._t_hb is not None:
                self.gap_samples.append((t, self.distance_m, t - self._t_hb))
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
                self.samples.append((t, self.distance_m, observed))
                if self.curve:
                    return self._onset("loss", observed > self.curve.upper_at(self.distance_m), t,
                                       lambda: self._ev(t, "excess_loss", observed_loss=round(observed, 3),
                                                        windows_lost=lost))
        return []

    def tick(self, t):
        out = []
        if self._t_hb is not None and self.gap_curve is not None:
            silent = t - self._t_hb
            limit = self.gap_curve.upper_at(self.distance_m)
            out += self._onset("gap", silent > limit, t,
                               lambda: self._ev(t, "telemetry_gap", silent_s=round(silent, 1),
                                                expected_silence_upper=round(limit, 1)))
        congested = self._t_congested is not None and t - self._t_congested >= self.congestion_s
        out += self._onset("congestion", congested, t, lambda: self._ev(t, "radio_congestion"))
        return out


# -- calibration ----------------------------------------------------------------------------

def run_samples(run: Path) -> tuple[list, list]:
    """(windowed loss, heartbeat silence) vs distance seen by the ground agent in one run."""
    from .commit import CommitRx
    from .ids import Ids, run_replay
    rx = CommitRx(bytes.fromhex((run / "onboard_commit.pub").read_text()))
    lm = LinkMonitor(rx)
    run_replay(Ids([rx, lm]), run / "ground")
    return lm.samples, lm.gap_samples


def onsets(series: list[tuple[float, float, float]], curve: BandCurve) -> int:
    n, above = 0, False
    for _, d, x in series:
        now = x > curve.upper_at(d)
        n += now and not above
        above = now
    return n


def _fit_to_budget(per_run, hours, budget_per_hour, **fit_kw) -> BandCurve:
    samples = [(d, x) for s in per_run for _, d, x in s]
    for k in [x / 2 for x in range(0, 41)]:
        curve = BandCurve.fit(samples, k, **fit_kw)
        n = sum(onsets(s, curve) for s in per_run)
        if n / hours <= budget_per_hour:
            break
    curve.meta = {"k": k, "false_onsets": n, "samples": len(samples),
                  "max_distance_m": round(max(d for d, _ in samples), 1)}
    return curve


def calibrate(runs: list[Path], budget_per_hour: float, bin_m: float = 50.0) -> dict:
    """Per statistic, the smallest k whose band meets the false-alarm budget on the
    calibration flights."""
    per_run = [run_samples(r) for r in runs]
    hours = sum(s[-1][0] - s[0][0] for s, _ in per_run if s) / 3600
    curves = {"loss": _fit_to_budget([s for s, _ in per_run], hours, budget_per_hour, bin_m=bin_m, floor=0.05),
              "gap": _fit_to_budget([g for _, g in per_run], hours, budget_per_hour, bin_m=bin_m, floor=3.0,
                                    cap=1e9)}
    for c in curves.values():
        c.meta.update(calibration_hours=round(hours, 3), budget_per_hour=budget_per_hour,
                      runs=[r.name for r in runs])
    return curves


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="+", type=Path, help="clean calibration run directories")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--budget", type=float, default=1.0, help="false excess_loss onsets per flight hour")
    a = ap.parse_args()
    runs = [r for r in a.runs if (r / "labels.json").exists()]
    curves = calibrate(runs, a.budget)
    save_curves(a.out, curves)
    for name, c in curves.items():
        print(name, json.dumps({k: v for k, v in c.meta.items() if k != "runs"}),
              "\n  upper by", c.bin_m, "m bin:", [round(u, 2) for u in c.upper])


if __name__ == "__main__":
    main()
