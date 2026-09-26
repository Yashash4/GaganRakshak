"""Per-run export for independent verification: one small JSON per recorded run with the
ground truth and the IDS's final output, and no computed metrics.

    python -m gaganrakshak.export --split calibration results/raw/calib3/*
writes results/runs/<split>/<run_id>.json with: run_id, scenario, seed, split, variant
("dev" | "held_out" | null for runs without an attack), status, attack {type, params},
events (labels, scenario time t), flight_s (takeoff to touchdown) and episodes
[{agent, class, severity, t_start, t_end}] from replaying the run through both agents, and
baseline_episodes in the same format: what stock ArduPilot itself flagged (see baseline.py).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .baseline import baseline_episodes
from .evaluate import evaluate

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


def export_run(run: Path, split: str, out_root: Path = ROOT / "results" / "runs") -> Path:
    if split not in SPLITS:
        raise ValueError(f"split must be one of {SPLITS}")
    labels = json.loads((run / "labels.json").read_text())
    events = [{k: v for k, v in e.items() if k != "wall"} for e in labels["events"] if e["event"] in KEEP]
    t = {e["event"]: e["t"] for e in events if e["event"] in ("takeoff", "touchdown")}
    attack = labels.get("attack")
    doc = {
        "run_id": labels["run_id"],
        "scenario": labels["scenario"],
        "seed": labels["seed"],
        "split": split,
        "variant": None if not attack else ("held_out" if labels.get("split") == "heldout" else "dev"),
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
        "episodes": [],
        "baseline_episodes": [],
    }
    if labels["status"] == "ok":
        doc["episodes"] = [
            {k: ep[k] for k in ("agent", "class", "severity", "t_start", "t_end")} for ep in evaluate(run)["episodes"]
        ]
        doc["baseline_episodes"] = baseline_episodes(run)
    out = out_root / split / f"{labels['run_id']}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=1))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="+", type=Path)
    ap.add_argument("--split", required=True, choices=SPLITS)
    ap.add_argument("--out", type=Path, default=ROOT / "results" / "runs")
    a = ap.parse_args()
    for run in a.runs:
        if (run / "labels.json").exists():
            print(export_run(run, a.split, a.out))


if __name__ == "__main__":
    main()
