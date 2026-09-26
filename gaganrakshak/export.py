"""Per-run export for independent verification: one small JSON per recorded run with the
ground truth and the IDS's final output, and no computed metrics.

    python -m gaganrakshak.export --split validation --raw-root results/raw results/raw/val2/*
    python -m gaganrakshak.export --split calibration --guard --raw-root results/raw results/raw/calib3/*
writes results/runs/<split>/<source>.json (source = the run's path under --raw-root, so runs of
the same scenario and seed from different batches stay apart; else the run id) with: run_id,
source, calibration (the calibration files the IDS used, with their git blob hashes), scenario,
seed, split, variant
("dev" | "held_out" | null for runs without an attack), status, attack {type, params},
events (labels, scenario time t), flight_s (takeoff to touchdown), physics {observable_s,
armed_s} (when the physics engine's heading became observable and its longest horizon armed),
distance_track [[t, d_m], ...] (about 1 Hz, see distance_track) and episodes
[{agent, class, severity, t_start, t_end, evidence_types}] from replaying the run through both agents, and
baseline_episodes in the same format: what stock ArduPilot itself flagged (see baseline.py).
The command exports only runs with status "ok" and lists the others with their status.
--guard exports only the runs the calibration guard accepts (calibration.select). A run recorded
as a test seed is exported only into the test split.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from .baseline import baseline_episodes
from .evaluate import CPCE_CALIB, ESTIMATOR_CALIB, LINK_CURVES, evaluate

ROOT = Path(__file__).resolve().parent.parent
SPLITS = ("calibration", "validation", "test")
KEEP = (
    "takeoff",
    "touchdown",
    "touchdown_not_seen",
    "land",
    "end",
    "operator",
    "attack_start",
    "attack_end",
    "attack_action",
    "benign_glitch_start",
    "benign_glitch_end",
)


def calibration_used() -> dict:
    """{file name: git blob hash} of the calibration files the IDS loads (present ones only)."""
    out = {}
    for f in (CPCE_CALIB, LINK_CURVES, ESTIMATOR_CALIB):
        if f.exists():
            data = f.read_bytes()
            out[f.name] = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
    return out


def distance_track(run: Path, t0: float, every_s: float = 1.0) -> list[list[float]]:
    """[[t, d_m], ...] about once per ``every_s``: horizontal distance from home of the position the
    ground agent received (GLOBAL_POSITION_INT, the autopilot's estimate, so a GNSS spoof moves it
    too), home = first fix after takeoff; scenario time."""
    from pymavlink import mavutil

    log = mavutil.mavlink_connection(str(run / "ground_D.tlog"), robust_parsing=True)
    out: list[list[float]] = []
    home = None
    while (m := log.recv_match(type="GLOBAL_POSITION_INT")) is not None:
        t = m._timestamp - t0
        if t < 0 or m.get_srcSystem() != 1 or not (m.lat or m.lon):
            continue
        lat, lon = m.lat / 1e7, m.lon / 1e7
        home = home or (lat, lon)
        if out and t - out[-1][0] < every_s:
            continue
        dn = math.radians(lat - home[0]) * 6371000.0
        de = math.radians(lon - home[1]) * 6371000.0 * math.cos(math.radians(home[0]))
        out.append([round(t, 2), round(math.hypot(dn, de), 1)])
    return out


def export_run(run: Path, split: str, out_root: Path = ROOT / "results" / "runs", source: str | None = None) -> Path:
    if split not in SPLITS:
        raise ValueError(f"split must be one of {SPLITS}")
    labels = json.loads((run / "labels.json").read_text())
    if labels.get("split") == "test" and split != "test":
        raise ValueError(f"{run}: a test seed; it may only be exported into the test split")
    source = source or labels["run_id"]
    events = [{k: v for k, v in e.items() if k != "wall"} for e in labels["events"] if e["event"] in KEEP]
    t = {e["event"]: e["t"] for e in events if e["event"] in ("takeoff", "touchdown")}
    attack = labels.get("attack")
    doc = {
        "run_id": labels["run_id"],
        "source": source,
        "calibration": calibration_used(),
        "scenario": labels["scenario"],
        "seed": labels["seed"],
        "split": split,
        "variant": None
        if not attack
        else labels.get("variant") or ("held_out" if labels.get("split") == "heldout" else "dev"),
        "status": labels["status"],
        "attack": {
            "type": attack["type"],
            "start_s": attack["start_s"],
            "end_s": attack["end_s"],
            "params": attack["params"],
        }
        if attack
        else None,
        "benign": labels.get("benign"),
        "events": events,
        "flight_s": round(t["touchdown"] - t["takeoff"], 2) if len(t) == 2 else None,
        "physics": {"observable_s": None, "armed_s": None},
        "distance_track": [],
        "episodes": [],
        "baseline_episodes": [],
    }
    if labels["status"] == "ok":
        ev = evaluate(run)
        doc["physics"] = ev["physics"]
        doc["episodes"] = [
            {k: ep[k] for k in ("agent", "class", "severity", "t_start", "t_end", "evidence_types")}
            for ep in ev["episodes"]
        ]
        doc["baseline_episodes"] = baseline_episodes(run)
        doc["distance_track"] = distance_track(run, labels["t0_wall"])
    out = out_root / split / f"{source}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=1))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="+", type=Path)
    ap.add_argument("--split", required=True, choices=SPLITS)
    ap.add_argument("--out", type=Path, default=ROOT / "results" / "runs")
    ap.add_argument("--raw-root", type=Path, help="name each export by the run's path under this directory")
    ap.add_argument("--guard", action="store_true", help="only runs the calibration guard accepts")
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    runs = []
    for r in a.runs:  # only flights that ran as planned; any other status is listed, not exported
        status = json.loads((r / "labels.json").read_text())["status"] if (r / "labels.json").exists() else None
        if status == "ok":
            runs.append(r)
        else:
            print(f"{a.split} skip {r}: status {status}")
    if a.guard:
        from .calibration import select

        runs = select(runs, workers=a.workers)
    sources = [str(r.resolve().relative_to(a.raw_root.resolve())) if a.raw_root else None for r in runs]
    if len({s or r.name for s, r in zip(sources, runs, strict=True)}) != len(runs):
        raise SystemExit("two runs would be written to the same file; pass --raw-root")
    with ProcessPoolExecutor(a.workers) as ex:
        for out in ex.map(export_run, runs, [a.split] * len(runs), [a.out] * len(runs), sources):
            print(out)


if __name__ == "__main__":
    main()
