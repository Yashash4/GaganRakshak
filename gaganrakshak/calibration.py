"""Calibration-run guard: thresholds are learned only from flights that are genuinely clean."""

from __future__ import annotations

import json
from pathlib import Path

HARNESS_ANOMALIES = {"touchdown_not_seen"}
# Evidence whose thresholds calibration learns: judged with uncalibrated defaults it would
# reject exactly the flights that show the behaviour to be learned. Everything else
# (protocol, signatures, altered/injected frames, integrity) disqualifies a run.
CALIBRATED_EVIDENCE = {
    "selective_commit_loss",
    "commit_timeout",
    "excess_loss",
    "telemetry_gap",
    "radio_congestion",
    "gnss_inertial_inconsistency",
    "gps_spoofing",
}


def usable(run: Path, check_ids: bool = True) -> tuple[bool, str]:
    """A calibration run must have flown as planned, contain no attack and no harness anomaly,
    and raise no IDS evidence on replay apart from the statistics being calibrated."""
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

        ev = [
            e
            for e in evaluate(run, link_curves=Path("/nonexistent"))["evidence"]
            if e["type"] not in CALIBRATED_EVIDENCE
        ]
        if ev:
            return False, f"IDS evidence: {sorted({(e['agent'], e['type']) for e in ev})}"
    return True, "ok"


def select(runs: list[Path], check_ids: bool = True, workers: int = 16) -> list[Path]:
    """The usable calibration runs; every decision is printed with its reason."""
    from concurrent.futures import ProcessPoolExecutor

    with ProcessPoolExecutor(workers) as ex:
        verdicts = list(ex.map(usable, runs, [check_ids] * len(runs)))
    keep = []
    for r, (ok, why) in zip(runs, verdicts, strict=True):
        print(f"calibration {'use ' if ok else 'SKIP'} {r.name}: {why}")
        if ok:
            keep.append(r)
    return keep
