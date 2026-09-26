"""The autopilot's own estimator consistency as NON-AUTHORITATIVE onboard evidence.

ArduPilot's EKF reports normalised innovation test ratios in EKF_STATUS_REPORT (velocity,
horizontal position, vertical position, compass, terrain altitude; 1.0 = the EKF's own gate).
A ratio that stays unusually high means the EKF's sensors disagree with its prediction. The EKF
is GNSS-aided, so a spoofer who moves slowly enough can steer it and keep the ratios low: this
evidence is corroboration only. It is LOW severity (an advisory, never an alarm on its own),
class ``gnss_integrity_advisory`` (``compass_anomaly`` for the compass ratio).

Evidence ``estimator_innovation_high``: a ratio stays above its threshold for ``persist_s``
(one report per excursion; the EKF_STATUS_REPORT flags are attached). Thresholds are learned per
ratio on clean calibration flights at a false-alarm budget (``learn``); a ratio that never moves
in calibration (e.g. terrain without a rangefinder) is left off.

    python -m gaganrakshak.estimator --budget 1.0 --out results/calibration/estimator.json \\
        results/raw/phys1/* results/raw/calib3/*
"""

from __future__ import annotations

import argparse
import json
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np

from .evidence import EvidenceEvent, Severity

RATIOS = ("velocity_variance", "pos_horiz_variance", "pos_vert_variance", "compass_variance", "terrain_alt_variance")
CLASS = {"compass_variance": "compass_anomaly"}  # all others: gnss_integrity_advisory
PERSIST_S = 2.0
GRID = np.round(np.arange(0.01, 5.0 + 1e-9, 0.01), 2)  # candidate thresholds (1.0 = the EKF's gate)
AUTOPILOT_SYSID = 1


class EstimatorMonitor:
    """IDS detector (onboard). ``calib`` = {"thresholds": {ratio: value or null}, "persist_s": s}."""

    def __init__(self, calib: dict, uav_id: int = 1):
        self.thr = {k: v for k, v in calib["thresholds"].items() if v is not None}
        self.persist_s = calib.get("persist_s", PERSIST_S)
        self.uav_id = uav_id
        self._since: dict[str, float] = {}  # ratio -> time it went above threshold
        self._reported: set[str] = set()

    def observe(self, msg, samples, direction, t):
        if direction != "D" or msg.get_type() != "EKF_STATUS_REPORT" or msg.get_srcSystem() != AUTOPILOT_SYSID:
            return []
        out = []
        for k, thr in self.thr.items():
            v = getattr(msg, k)
            if v <= thr:
                self._since.pop(k, None)
                self._reported.discard(k)
                continue
            since = self._since.setdefault(k, t)
            if t - since >= self.persist_s and k not in self._reported:
                self._reported.add(k)
                meta = {"ratio": k, "value": round(float(v), 3), "threshold": thr, "flags": int(msg.flags)}
                cls = CLASS.get(k, "gnss_integrity_advisory")
                out.append(
                    EvidenceEvent(
                        t, self.uav_id, "estimator", "estimator_innovation_high", v / thr, Severity.LOW, cls, meta
                    )
                )
        return out


def onsets(t: np.ndarray, v: np.ndarray, thr: float, persist_s: float) -> int:
    """Excursions above ``thr`` lasting at least ``persist_s`` (what the detector would report)."""
    above = np.concatenate([[False], v > thr, [False]]).astype(np.int8)
    d = np.diff(above)
    starts, ends = np.flatnonzero(d == 1), np.flatnonzero(d == -1) - 1
    return int(np.sum(t[ends] - t[starts] >= persist_s))


def extract(run: Path) -> dict:
    """{ratio: (times, values)} of the autopilot's EKF_STATUS_REPORT in a run's onboard downlink."""
    from pymavlink import mavutil

    log = mavutil.mavlink_connection(str(run / "onboard_D.tlog"), robust_parsing=True)
    ts, vs = [], []
    while (m := log.recv_match(type="EKF_STATUS_REPORT")) is not None:
        if m.get_srcSystem() == AUTOPILOT_SYSID:
            ts.append(m._timestamp)
            vs.append([getattr(m, k) for k in RATIOS])
    t, v = np.array(ts), np.array(vs).reshape(-1, len(RATIOS))
    return {k: (t, v[:, i]) for i, k in enumerate(RATIOS)}


def poisson_upper(k: int, hours: float, conf: float = 0.95) -> float:
    """One-sided upper confidence bound on an event rate per hour, k events in ``hours``."""
    from scipy.stats import chi2

    return float(chi2.ppf(conf, 2 * (k + 1)) / 2 / hours)


def learn(series: list[dict], budget_per_hour: float, persist_s: float = PERSIST_S) -> dict:
    """Per ratio, the smallest grid threshold from which on every larger one the clean flights
    give at most (budget / active ratios) onsets per hour; the budget is shared by the ratios."""
    hours = sum(float(s[RATIOS[0]][0][-1] - s[RATIOS[0]][0][0]) for s in series if len(s[RATIOS[0]][0])) / 3600
    active = [k for k in RATIOS if any(np.any(s[k][1] != s[k][1][0]) for s in series if len(s[k][1]))]
    share = budget_per_hour / max(1, len(active))
    thresholds: dict[str, float | None] = {k: None for k in RATIOS}
    per_ratio: dict[str, dict] = {}
    for k in active:
        counts = np.array([sum(onsets(s[k][0], s[k][1], thr, persist_s) for s in series) for thr in GRID])
        ok = counts / hours <= share
        bad = np.flatnonzero(~ok)
        i = 0 if not len(bad) else bad[-1] + 1
        if i >= len(GRID):
            continue  # nothing on the grid meets the share: leave the ratio off
        thresholds[k] = float(GRID[i])
        per_ratio[k] = {
            "false_onsets": int(counts[i]),
            "upper95_per_hour": round(poisson_upper(int(counts[i]), hours), 3),
        }
    total = int(sum(r["false_onsets"] for r in per_ratio.values()))
    return {
        "thresholds": thresholds,
        "persist_s": persist_s,
        "meta": {
            "calibration_hours": round(hours, 3),
            "budget_per_hour": budget_per_hour,
            "false_onsets": total,
            "false_onsets_per_hour": round(total / hours, 3) if hours else None,
            "upper95_per_hour": round(poisson_upper(total, hours), 3) if hours else None,
            "per_ratio": per_ratio,
            "off": [k for k in RATIOS if thresholds[k] is None],
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="+", type=Path)
    ap.add_argument("--budget", type=float, default=1.0, help="false onsets per hour, all ratios together")
    ap.add_argument("--persist", type=float, default=PERSIST_S)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    from .calibration import select

    runs = select([r for r in a.runs if (r / "labels.json").exists()], workers=a.workers)
    with ProcessPoolExecutor(a.workers) as ex:
        series = list(ex.map(extract, runs))
    calib = learn(series, a.budget, a.persist)
    calib["meta"]["runs"] = [r.name for r in runs]
    calib["meta"]["source"] = "clean SITL calibration flights (guard-selected)"
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(calib, indent=1))
    print(json.dumps({k: v for k, v in calib["meta"].items() if k != "runs"}, indent=1), calib["thresholds"])


if __name__ == "__main__":
    main()
