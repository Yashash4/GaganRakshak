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
- ``telemetry_gap``     FC heartbeat silence longer than random loss explains at this distance:
                        with per-frame loss p (learned band), s seconds of silence has probability
                        ~p^s; the limit is where that falls below the false-alarm budget
                        (outage, jamming burst)
- ``radio_congestion``  air-side radio buffer below ``txbuf_min`` % for ``congestion_s`` (flood)
Metadata carries distance, expected and observed loss so fusion can weigh benign fades.
Distance comes from telemetry and is only trusted while that telemetry is credible
(``trusted_distance``); otherwise the nearest (strictest) band applies.

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
    def fit(
        cls,
        samples: list[tuple[float, float]],
        k: float,
        bin_m: float = 50.0,
        floor: float = 0.05,
        cap: float = 1.0,
        min_per_bin: int = 5,
    ) -> BandCurve:
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
    def from_dict(cls, d: dict) -> BandCurve:
        return cls(d["bin_m"], d["upper"], d.get("meta"))


LossCurve = BandCurve  # loss-vs-distance band


def save_curves(path: Path, curves: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({k: c if isinstance(c, dict) else c.to_dict() for k, c in curves.items()}, indent=1))


def load_curves(path: Path) -> dict:
    """{"loss": BandCurve, "gap": BandCurve, "commit": {CommitRx settings}}"""
    d = json.loads(Path(path).read_text())
    out = {k: BandCurve.from_dict(v) for k, v in d.items() if k != "commit"}
    if "commit" in d:
        out["commit"] = {k: v for k, v in d["commit"].items() if k != "meta"}
    return out


class LinkMonitor:
    def __init__(
        self,
        commit_rx,
        uav_id: int = 1,
        curves: dict | None = None,
        window: int = 10,
        min_frames: int = 100,
        gap_s: float = 3.0,
        txbuf_min: int = 20,
        congestion_s: float = 3.0,
        vmax: float = 30.0,
        distrust_s: float = 60.0,
        budget_per_hour: float = 1.0,
    ):
        self.rx = commit_rx
        self.uav_id = uav_id
        curves = curves or {}  # none: record samples only (calibration); no loss/gap evidence
        self.curve = curves.get("loss")
        self.budget_per_hour = budget_per_hour
        self.window, self.min_frames = window, min_frames
        self.gap_s, self.txbuf_min, self.congestion_s = gap_s, txbuf_min, congestion_s
        self.home = None
        self.distance_m = 0.0  # reported distance (telemetry)
        self.vmax, self.distrust_s = vmax, distrust_s
        self._last_pos = None
        self._t_implausible = None
        self.samples: list[tuple[float, float, float]] = []  # (t, distance, windowed loss)
        self.gap_samples: list[tuple[float, float, float]] = []  # (t, distance, heartbeat silence)
        self._t_hb = None
        self._in = {"loss": False, "gap": False, "congestion": False}
        self._t_congested = None

    def trusted_distance(self, t) -> tuple[float, bool]:
        """Reported distance, unless the telemetry that carries it is in doubt: it moved
        implausibly fast, or the commitments recently showed telemetry manipulation. A spoofed
        far position must not widen the expected-loss band, so doubt means the nearest band."""
        m = getattr(self.rx, "t_last_manipulation", None)
        doubt = (self._t_implausible is not None and t - self._t_implausible < self.distrust_s) or (
            m is not None and t - m < self.distrust_s
        )
        return (0.0, False) if doubt else (self.distance_m, True)

    def silence_limit(self, distance_m: float, floor_s: float = 3.0) -> float:
        """Heartbeat (1 Hz) silence that random loss explains less often than the budget:
        P(silence >= s) ~ p^(s-1) with p the learned per-frame loss band at this distance."""
        p = min(self.curve.upper_at(distance_m), 0.999)
        if p <= 0:
            return floor_s
        alpha = self.budget_per_hour / 3600.0
        return max(floor_s, 1.0 + math.log(alpha) / math.log(p))

    def _ev(self, t, kind, **meta):
        d, trusted = self.trusted_distance(t)
        meta.update(distance_m=round(self.distance_m, 1), distance_trusted=trusted)
        if self.curve:
            meta["expected_loss_upper"] = round(self.curve.upper_at(d), 3)
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
            if self._last_pos is not None and t > self._last_pos[0]:
                speed = math.hypot(dn - self._last_pos[1], de - self._last_pos[2]) / (t - self._last_pos[0])
                if speed > self.vmax:
                    self._t_implausible = t
            self._last_pos = (t, dn, de)
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
                    d, _ = self.trusted_distance(t)
                    return self._onset(
                        "loss",
                        observed > self.curve.upper_at(d),
                        t,
                        lambda: self._ev(t, "excess_loss", observed_loss=round(observed, 3), windows_lost=lost),
                    )
        return []

    def tick(self, t):
        out = []
        if self.curve is not None:  # beyond the calibrated range the last band is extrapolated
            limit = self.curve.meta.get("max_distance_m")
            if limit is not None:
                far = self.trusted_distance(t)[0] > limit
                if far and not self._in.get("far"):
                    out.append(
                        EvidenceEvent(
                            t,
                            self.uav_id,
                            "link_monitor",
                            "outside_calibrated_range",
                            0.0,
                            Severity.INFO,
                            None,
                            {"distance_m": round(self.distance_m, 1), "calibrated_max_m": limit},
                        )
                    )
                self._in["far"] = far
        if self._t_hb is not None and self.curve is not None:
            silent = t - self._t_hb
            limit = self.silence_limit(self.trusted_distance(t)[0])
            out += self._onset(
                "gap",
                silent > limit,
                t,
                lambda: self._ev(t, "telemetry_gap", silent_s=round(silent, 1), expected_silence_upper=round(limit, 1)),
            )
        congested = self._t_congested is not None and t - self._t_congested >= self.congestion_s
        out += self._onset("congestion", congested, t, lambda: self._ev(t, "radio_congestion"))
        return out


# -- calibration ----------------------------------------------------------------------------


def run_samples(run: Path) -> tuple[list, list, list]:
    """(windowed loss, heartbeat silence) vs distance seen by the ground agent in one run, and
    the commitment-vs-frame loss history used to learn the commitment loss model."""
    from .commit import CommitRx
    from .ids import Ids, run_replay

    rx = CommitRx(bytes.fromhex((run / "onboard_commit.pub").read_text()))
    lm = LinkMonitor(rx)
    run_replay(Ids([rx, lm]), run / "ground")
    return lm.samples, lm.gap_samples, rx.loss_pairs


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
    curve.meta = {
        "k": k,
        "false_onsets": n,
        "samples": len(samples),
        "max_distance_m": round(max(d for d, _ in samples), 1),
    }
    return curve


def fit_commit_loss(pairs: list, hours: float, budget_per_hour: float, min_lost: int = 5) -> dict:
    """Commitments are longer than telemetry frames and lost more often. Learn gamma in
    p_commit = 1 - (1 - p_frame)^gamma (least squares in log space), then the smallest z for
    the selective-loss test that meets the false-alarm budget on these clean flights."""
    xy = [
        (math.log(1 - f), math.log(1 - c))
        for run in pairs
        for f, c, n, _ in run
        if n >= 20 and 0.02 < f < 0.98 and c < 0.98
    ]
    gamma = sum(x * y for x, y in xy) / sum(x * x for x, _ in xy) if len(xy) >= 20 else 1.0
    for z in [x / 4 for x in range(4, 81)]:
        n_on = 0
        for run in pairs:
            above = False
            for f, c, n, lost in run:
                p_exp = 1 - (1 - min(f, 0.999)) ** gamma
                sd = math.sqrt(max(p_exp * (1 - p_exp), 1.0 / max(n, 1)) / max(n, 1))
                now = lost >= min_lost and n and (c - p_exp) / sd > z
                n_on += now and not above
                above = now
        if n_on / hours <= budget_per_hour:
            break
    return {
        "commit_loss_exponent": round(gamma, 3),
        "selective_z": z,
        "meta": {"points": len(xy), "false_onsets": n_on},
    }


def calibrate(runs: list[Path], budget_per_hour: float, bin_m: float = 50.0) -> dict:
    """Per statistic, the smallest k (or z) meeting the false-alarm budget on the clean
    calibration flights; runs that are not clean are rejected first."""
    from .calibration import select

    runs = select(runs)
    per_run = [run_samples(r) for r in runs]
    hours = sum(s[-1][0] - s[0][0] for s, _, _ in per_run if s) / 3600
    curves = {"loss": _fit_to_budget([s for s, _, _ in per_run], hours, budget_per_hour, bin_m=bin_m, floor=0.05)}
    # heartbeat-silence limits follow from the loss band (LinkMonitor.silence_limit); report how
    # the calibration flights' longest silences compare
    lm = LinkMonitor(None, curves=curves)
    curves["loss"].meta["silence_exceedances"] = sum(
        1 for _, g, _ in per_run for _, d, x in g if x > lm.silence_limit(d)
    )
    for c in curves.values():
        c.meta.update(calibration_hours=round(hours, 3), budget_per_hour=budget_per_hour, runs=[r.name for r in runs])
    commit = fit_commit_loss([p for _, _, p in per_run], hours, budget_per_hour)
    commit["meta"].update(calibration_hours=round(hours, 3), budget_per_hour=budget_per_hour)
    return {**curves, "commit": commit}


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
        if isinstance(c, dict):
            print(name, json.dumps(c))
            continue
        print(
            name,
            json.dumps({k: v for k, v in c.meta.items() if k != "runs"}),
            "\n  upper by",
            c.bin_m,
            "m bin:",
            [round(u, 2) for u in c.upper],
        )


if __name__ == "__main__":
    main()
