"""Calibration-run guard: thresholds are learned only from flights that are genuinely clean."""

from __future__ import annotations

import json
from pathlib import Path

HARNESS_ANOMALIES = {"touchdown_not_seen"}


def usable(run: Path, check_ids: bool = True) -> tuple[bool, str]:
    """A calibration run must have flown as planned, contain no attack and no harness anomaly,
    and raise no IDS episode when replayed (with default, uncalibrated settings)."""
    labels = json.loads((run / "labels.json").read_text())
    if labels["status"] != "ok":
        return False, f"status {labels['status']}"
    if labels.get("attack"):
        return False, "contains an attack"
    bad = [e["event"] for e in labels["events"] if e["event"] in HARNESS_ANOMALIES]
    if bad:
        return False, f"harness anomaly: {bad}"
    if check_ids:
        from .evaluate import evaluate
        eps = evaluate(run, link_curves=Path("/nonexistent"))["episodes"]
        if eps:
            return False, f"IDS episodes: {sorted({(e['agent'], e['class']) for e in eps})}"
    return True, "ok"


def select(runs: list[Path], check_ids: bool = True) -> list[Path]:
    keep = []
    for r in runs:
        ok, why = usable(r, check_ids)
        print(f"calibration {'use ' if ok else 'SKIP'} {r.name}: {why}")
        if ok:
            keep.append(r)
    return keep
