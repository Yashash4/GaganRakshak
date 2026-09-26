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

Each agent runs in its own process (a fresh interpreter, one after the other), so its CPU and
memory are its own. Per agent: message count, latency p50/p95/p99/max overall and per message type, throughput,
CPU % of one core (user + system time / wall time), resident memory at start and peak, time per
detector, and the alert latency (first episode opened between attack start and attack end +
``ALERT_WINDOW_S``, scenario time). Onboard, the physics engine's cost is reported per new GNSS
fix (all horizons) and per IMU sample, with the IMU rate of the run. Tlog reading and parsing are
outside the timed section. The timings are kept as packed doubles; their size is reported
(timing_buffers_mb) and is part of the peak memory. The machine's load average is recorded: numbers from a busy machine
are not comparable with numbers from an idle one.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import resource
import time
from array import array
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np

from .evaluate import detectors
from .ids import Ids, replay_tlogs

PLATFORM = "DGX Spark"
ALERT_WINDOW_S = 10.0


def _pct(xs) -> dict:
    if not len(xs):
        return {}
    a = np.asarray(xs) * 1000.0
    return {f"p{q}_ms": round(float(np.percentile(a, q)), 4) for q in (50, 95, 99)} | {
        "max_ms": round(float(a.max()), 4),
        "n": len(xs),
    }


def _rss_mb() -> float:
    return int(Path("/proc/self/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 2**20


class Timed:
    """Detector proxy: time spent in observe() per message type. GPS_RAW_INT is split into new
    fixes and repeats of the last fix (the stream is faster than the receiver's fix rate)."""

    def __init__(self, det):
        self.det = det
        self.times: dict[str, array] = defaultdict(lambda: array("d"))  # 8 bytes a sample
        self._fix = None

    def observe(self, msg, samples, direction, t):
        s = time.perf_counter()
        out = self.det.observe(msg, samples, direction, t)
        dt = time.perf_counter() - s
        key = msg.get_type()
        if key == "GPS_RAW_INT" and direction == "D":
            key = "GPS_RAW_INT(new fix)" if msg.time_usec != self._fix else "GPS_RAW_INT(repeat)"
            self._fix = msg.time_usec
        self.times[key].append(dt)
        return out

    def __getattr__(self, name):  # tick() and anything else: the detector's own
        return getattr(self.det, name)


def replay(ids: Ids, prefix: Path, paced: bool, tick_s: float = 0.1) -> dict:
    """Feed a tlog pair through ``ids`` (ticks as ``ids.run_replay``); timing per message."""
    # timings kept as packed doubles: the measurement must not inflate the memory it reports
    lat = array("d")
    by_type: dict[str, array] = defaultdict(lambda: array("d"))
    late = array("d")
    late_max: dict[int, float] = {}  # 10 s bin of run time -> largest lateness
    t_first: float | None = None
    next_tick = t = 0.0
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
            late.append(start - due)
            k = int((t - t_first) // 10)
            late_max[k] = max(late_max.get(k, 0.0), start - due)
        else:
            due = start
        while t >= next_tick:
            ids.tick(next_tick)
            next_tick += tick_s
        ids.feed(msg, direction, t)
        dt = time.perf_counter() - due
        lat.append(dt)
        by_type[msg.get_type()].append(dt)
    wall = time.perf_counter() - w0
    ru1 = resource.getrusage(resource.RUSAGE_SELF)
    cpu = (ru1.ru_utime - ru0.ru_utime) + (ru1.ru_stime - ru0.ru_stime)
    out: dict[str, Any] = {
        "messages": len(lat),
        "recorded_s": round(t - t_first, 3) if t_first is not None else 0.0,
        "wall_s": round(wall, 3),
        "msgs_per_s": round(len(lat) / wall, 1) if wall else None,
        "cpu_pct_one_core": round(100.0 * cpu / wall, 1) if wall else None,
        "latency": _pct(lat),
        "latency_by_type": {k: _pct(v) for k, v in sorted(by_type.items(), key=lambda kv: -len(kv[1]))},
    }
    if paced and late:
        out["lateness"] = _pct(late)
        out["lateness_max_per_10s_s"] = [round(late_max[k], 4) for k in sorted(late_max)]
    out["timing_buffers_mb"] = round((sum(a.buffer_info()[1] for a in (lat, late, *by_type.values())) * 8) / 2**20, 1)
    return out


def _agent(side: str, run: Path, paced: bool, make, t0: float, start, end, q) -> None:
    rss0 = _rss_mb()
    dets = [Timed(d) for d in make(side, run)]
    ids = Ids(dets)
    r = replay(ids, run / side, paced)
    r["rss_start_mb"] = round(rss0, 1)
    r["peak_rss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 1)  # Linux: KiB
    r["timing_buffers_mb"] += round(sum(len(a) * 8 for d in dets for a in d.times.values()) / 2**20, 1)
    r["detector_s"] = {type(d.det).__name__: round(sum(sum(v) for v in d.times.values()), 3) for d in dets}
    physics = next((d for d in dets if type(d.det).__name__ == "Cpce"), None)
    if physics is not None:
        imu = physics.times.get("RAW_IMU", array("d"))
        r["physics"] = {
            "horizons_s": list(physics.det.res.horizons),
            "per_gnss_fix": _pct(physics.times.get("GPS_RAW_INT(new fix)", array("d"))),
            "per_imu_sample": _pct(imu),
            "imu_rate_hz": round(len(imu) / r["recorded_s"], 1) if r["recorded_s"] else None,
        }
    first = None
    if start is not None:
        stop = (end if end is not None else start) + ALERT_WINDOW_S
        eps = sorted((ep.t_start - t0, ep.attack_class) for ep in ids.tracker.episodes)
        first = next(({"latency_s": round(ts - start, 3), "class": c} for ts, c in eps if start <= ts <= stop), None)
    r["first_alert"] = first
    q.put(r)


def measure(run: Path, paced: bool = False, make=detectors) -> dict:
    labels = json.loads((run / "labels.json").read_text())
    start = next((e["t"] for e in labels["events"] if e["event"] == "attack_start"), None)
    end = next((e["t"] for e in labels["events"] if e["event"] == "attack_end"), None)
    out: dict[str, Any] = {
        "platform": PLATFORM,
        "cpus": os.cpu_count(),
        "load_avg_1m_at_start": round(os.getloadavg()[0], 2),
        "run_id": labels["run_id"],
        "attack": labels["attack"]["type"] if labels.get("attack") else None,
        "mode": "paced" if paced else "fast",
        "agents": {},
    }
    ctx = mp.get_context("spawn")  # fresh process: its own memory; fork is unsafe in a threaded parent
    for side in ("onboard", "ground"):
        q = ctx.Queue()
        p = ctx.Process(target=_agent, args=(side, run, paced, make, labels["t0_wall"], start, end, q))
        p.start()
        out["agents"][side] = q.get()
        p.join()
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
