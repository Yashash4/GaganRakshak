"""Consistency of the navigation receiver with an independent second GNSS reference (onboard).

Optional extension. A second receiver on an independent constellation or band (in SITL: a second
simulated receiver with its own error process, a stand-in e.g. for NavIC) is not used for
navigation; the autopilot navigates on GPS1 only (configs/dual_gnss.parm). A spoofer of the
navigation receiver's signals moves GPS1 but not the reference, so their horizontal separation
grows beyond what two independent receivers disagree by on clean flights. An attacker who spoofs
both references coherently, or jams the reference while spoofing the navigation receiver (fixes
without a 3D fix are not compared), silences this statistic; detection then falls back to the
single-GPS physics.

Evidence ``gnss_reference_disagreement`` [gps_spoofing, MEDIUM]: the separation stays above the
learned threshold for ``persist_s`` (one report per excursion). The threshold is learned on clean
calibration flights with the reference on, at the statistic's own false-alarm share (``learn``),
never from the simulator's error model.

    python -m gaganrakshak.dual_gnss --budget 0.2 --out results/calibration_dual/dual_gnss.json \\
        results/raw/calib_dual/*
"""

from __future__ import annotations

import argparse
import json
import math
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np

from .estimator import onsets, poisson_upper
from .evidence import EvidenceEvent, Severity

PERSIST_S = 5.0
MAX_DT_S = 0.3  # fixes further apart in time than this are not compared
GRID = np.round(np.arange(1.0, 150.0 + 1e-9, 0.5), 1)  # candidate thresholds, m
AUTOPILOT_SYSID = 1
M_PER_DEG = 6371000.0 * math.pi / 180


class Separation:
    """Horizontal GPS1 - GPS2 separation at each reference fix (GPS1 carried to the reference fix
    time with its own velocity when the two fixes are not simultaneous)."""

    def __init__(self):
        self.g1: tuple | None = None  # (fix time s, lat, lon, vn, ve)

    def observe(self, msg) -> float | None:
        name = msg.get_type()
        if name not in ("GPS_RAW_INT", "GPS2_RAW") or msg.get_srcSystem() != AUTOPILOT_SYSID or msg.fix_type < 3:
            return None
        if name == "GPS_RAW_INT":
            vn = ve = 0.0
            if msg.vel != 65535 and msg.cog != 65535:
                v, c = msg.vel / 100.0, math.radians(msg.cog / 100.0)
                vn, ve = v * math.cos(c), v * math.sin(c)
            self.g1 = (msg.time_usec / 1e6, msg.lat / 1e7, msg.lon / 1e7, vn, ve)
            return None
        if name != "GPS2_RAW" or self.g1 is None:
            return None
        t1, lat1, lon1, vn, ve = self.g1
        dt = msg.time_usec / 1e6 - t1
        if abs(dt) > MAX_DT_S:
            return None
        dn = (lat1 - msg.lat / 1e7) * M_PER_DEG + vn * dt
        de = (lon1 - msg.lon / 1e7) * M_PER_DEG * math.cos(math.radians(lat1)) + ve * dt
        return math.hypot(dn, de)


class DualGnssMonitor:
    """IDS detector (onboard). ``calib`` = {"threshold_m": T, "persist_s": s}."""

    def __init__(self, calib: dict, uav_id: int = 1):
        self.thr = calib["threshold_m"]
        self.persist_s = calib.get("persist_s", PERSIST_S)
        self.uav_id = uav_id
        self.sep = Separation()
        self._since: float | None = None
        self._reported = False

    def observe(self, msg, samples, direction, t):
        if direction != "D":
            return []
        d = self.sep.observe(msg)
        if d is None:
            return []
        if d <= self.thr:
            self._since, self._reported = None, False
            return []
        if self._since is None:
            self._since = t
        if t - self._since >= self.persist_s and not self._reported:
            self._reported = True
            meta = {"separation_m": round(d, 1), "threshold_m": self.thr}
            return [
                EvidenceEvent(
                    t,
                    self.uav_id,
                    "dual_gnss",
                    "gnss_reference_disagreement",
                    d / self.thr,
                    Severity.MEDIUM,
                    "gps_spoofing",
                    meta,
                )
            ]
        return []


def extract(run: Path) -> tuple[np.ndarray, np.ndarray]:
    """(times, separations) of a run's onboard downlink, airborne part only."""
    from pymavlink import mavutil

    import gaganrakshak.mavlink  # noqa: F401  (registers the GaganRakshak messages)

    labels = json.loads((run / "labels.json").read_text())
    ev = {e["event"]: e["t"] for e in labels["events"]}
    t0 = labels["t0_wall"]
    lo, hi = t0 + ev.get("takeoff", 0.0), t0 + ev.get("touchdown", ev.get("end", math.inf))
    sep = Separation()
    ts, ds = [], []
    log = mavutil.mavlink_connection(str(run / "onboard_D.tlog"), robust_parsing=True)
    while (m := log.recv_match(type=["GPS_RAW_INT", "GPS2_RAW"])) is not None:
        d = sep.observe(m)
        if d is not None and lo <= m._timestamp <= hi:
            ts.append(m._timestamp)
            ds.append(d)
    return np.array(ts), np.array(ds)


def learn(
    series: list[tuple[np.ndarray, np.ndarray]],
    hours: float,
    budget_per_hour: float,
    persist_s: float = PERSIST_S,
    names: list[str] | None = None,
) -> dict:
    """The smallest grid threshold from which on every larger one the clean flights give at most
    ``budget_per_hour`` onsets per airborne hour. ``names`` (one per series) identify, in the
    metadata, the flights with the largest separation and with onsets at the threshold."""
    counts = np.array([sum(onsets(t, d, thr, persist_s) for t, d in series if len(t)) for thr in GRID])
    bad = np.flatnonzero(counts / hours > budget_per_hour)
    i = 0 if not len(bad) else bad[-1] + 1
    if i >= len(GRID):
        raise ValueError("no threshold on the grid meets the budget")
    n = int(counts[i])
    names = names or [str(k) for k in range(len(series))]
    peaks = [(float(d.max()), nm) for (_, d), nm in zip(series, names, strict=True) if len(d)]
    peak, peak_run = max(peaks, default=(0.0, None))
    at_t = [nm for (t, d), nm in zip(series, names, strict=True) if len(t) and onsets(t, d, float(GRID[i]), persist_s)]
    return {
        "threshold_m": float(GRID[i]),
        "persist_s": persist_s,
        "meta": {
            "calibration_hours": round(hours, 3),
            "budget_per_hour": budget_per_hour,
            "false_onsets": n,
            "upper95_per_hour": round(poisson_upper(n, hours), 3),
            "peak_clean_separation_m": round(peak, 2),
            "peak_clean_separation_run": peak_run,
            "onset_runs": at_t,
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="+", type=Path)
    ap.add_argument("--budget", type=float, default=0.2, help="false onsets per airborne hour")
    ap.add_argument("--persist", type=float, default=PERSIST_S)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    from .calibration import airborne_hours, select

    # flew as planned, no attack, reference receiver present; the base detectors' own verdicts on
    # these flights do not matter for learning the separation
    runs = [r for r in a.runs if (r / "labels.json").exists()]
    runs = [
        r
        for r in select(runs, check_ids=False, workers=a.workers)
        if json.loads((r / "labels.json").read_text()).get("gnss2")
    ]
    with ProcessPoolExecutor(a.workers) as ex:
        series = list(ex.map(extract, runs))
    calib = learn(series, airborne_hours(runs), a.budget, a.persist, [r.name for r in runs])
    calib["meta"]["runs"] = [r.name for r in runs]
    calib["meta"]["source"] = "clean SITL calibration flights with the reference receiver on"
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(calib, indent=1))
    print(json.dumps({k: v for k, v in calib["meta"].items() if k != "runs"}, indent=1), calib["threshold_m"])


if __name__ == "__main__":
    main()
