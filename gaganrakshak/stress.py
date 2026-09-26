"""IDS stress measurement: replay a recorded run through both agents' detectors and measure
what the IDS costs and whether it keeps up.

    python -m gaganrakshak.stress results/raw/<batch>/<run> [--paced] [--out results/stress]

Modes
- fast (default): messages are processed back to back; latency = time to process one message
  (adapter, detectors, fusion and the periodic ticks due before it). Gives the throughput ceiling.
- paced (--paced): each message is released at its recorded time, as on the aircraft; latency =
  release to processed, so it includes waiting behind earlier messages. ``lateness`` (how far
  behind real time the IDS is when it takes a message) is the input backlog in seconds; if it
  grows over the run, the IDS cannot keep up with that traffic.
Per agent: message count, latency p50/p95/p99/max, throughput, CPU % of one core (user + system
time / wall time, from getrusage), peak RSS of the process, and the alert latency: first episode
opened between attack start and attack end + ``ALERT_WINDOW_S``, in scenario time. Tlog reading
and parsing are outside the timed section in fast mode.
"""

from __future__ import annotations

import argparse
import json
import resource
import time
from pathlib import Path
from typing import Any

import numpy as np

from .evaluate import detectors
from .ids import Ids, replay_tlogs

PLATFORM = "DGX Spark"
ALERT_WINDOW_S = 10.0


def _pct(xs: list[float]) -> dict:
    if not xs:
        return {}
    a = np.array(xs) * 1000.0
    return {f"p{q}_ms": round(float(np.percentile(a, q)), 4) for q in (50, 95, 99)} | {
        "max_ms": round(float(a.max()), 4)
    }


def replay(ids: Ids, prefix: Path, paced: bool, tick_s: float = 0.1) -> dict:
    """Feed a tlog pair through ``ids`` (ticks as ``ids.run_replay``); timing per message."""
    lat: list[float] = []
    late: list[tuple[float, float]] = []  # (run time, lateness)
    t_first: float | None = None
    next_tick = 0.0
    ru0, w0 = resource.getrusage(resource.RUSAGE_SELF), time.perf_counter()
    for t, direction, msg in replay_tlogs(prefix):
        if t_first is None:
            t_first = next_tick = t
        start = time.perf_counter()
        if paced:
            due = w0 + (t - t_first)
            if start < due:
                time.sleep(due - start)
                start = due
            late.append((t - t_first, start - due))
        else:
            due = start
        while t >= next_tick:
            ids.tick(next_tick)
            next_tick += tick_s
        ids.feed(msg, direction, t)
        lat.append(time.perf_counter() - due)
    wall = time.perf_counter() - w0
    ru1 = resource.getrusage(resource.RUSAGE_SELF)
    cpu = (ru1.ru_utime - ru0.ru_utime) + (ru1.ru_stime - ru0.ru_stime)
    out: dict[str, Any] = {
        "messages": len(lat),
        "wall_s": round(wall, 3),
        "msgs_per_s": round(len(lat) / wall, 1) if wall else None,
        "latency": _pct(lat),
        "cpu_pct_one_core": round(100.0 * cpu / wall, 1) if wall else None,
    }
    if paced and late:
        bins: dict[int, float] = {}
        for rt, lt in late:
            bins[int(rt // 10)] = max(bins.get(int(rt // 10), 0.0), lt)
        out["lateness"] = _pct([lt for _, lt in late])
        out["lateness_max_per_10s_s"] = [round(bins[k], 4) for k in sorted(bins)]
    return out


def measure(run: Path, paced: bool = False, make=detectors) -> dict:
    labels = json.loads((run / "labels.json").read_text())
    t0 = labels["t0_wall"]
    start = next((e["t"] for e in labels["events"] if e["event"] == "attack_start"), None)
    end = next((e["t"] for e in labels["events"] if e["event"] == "attack_end"), None)
    out: dict[str, Any] = {
        "platform": PLATFORM,
        "run_id": labels["run_id"],
        "attack": labels["attack"]["type"] if labels.get("attack") else None,
        "mode": "paced" if paced else "fast",
        "agents": {},
    }
    for side in ("onboard", "ground"):
        ids = Ids(make(side, run))
        r = replay(ids, run / side, paced)
        first = None
        if start is not None:
            stop = (end if end is not None else start) + ALERT_WINDOW_S
            eps = sorted((ep.t_start - t0, ep.attack_class) for ep in ids.tracker.episodes)
            first = next(
                ({"latency_s": round(ts - start, 3), "class": c} for ts, c in eps if start <= ts <= stop), None
            )
        r["first_alert"] = first
        out["agents"][side] = r
    out["peak_rss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 1)  # Linux: KiB
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="+", type=Path)
    ap.add_argument("--paced", action="store_true", help="release messages at their recorded times")
    ap.add_argument("--out", type=Path, default=None, help="directory for <run_id>.<mode>.json")
    a = ap.parse_args()
    for run in a.runs:
        r = measure(run, a.paced)
        if a.out:
            a.out.mkdir(parents=True, exist_ok=True)
            (a.out / f"{r['run_id']}.{r['mode']}.json").write_text(json.dumps(r, indent=1))
        print(json.dumps(r, indent=1))


if __name__ == "__main__":
    main()
