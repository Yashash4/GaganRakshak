"""Replay a recorded run through both IDS agents and report evidence and alerts in
scenario time (t = 0 at the takeoff command), next to the run's ground-truth labels.

    python -m gaganrakshak.evaluate results/raw/<run> [--events]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .cmd_sign import CmdVerifier
from .commit import CommitRx
from .cpce import Cpce
from .estimator import EstimatorMonitor
from .ids import Ids, run_replay
from .integrity import IntegrityMonitor, load_baseline
from .link_monitor import LinkMonitor, load_curves
from .protocol import for_agent
from .response import ResponseMonitor

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "configs" / "baseline" / "ardupilot_copter_sitl"
LINK_CURVES = ROOT / "results" / "calibration" / "link_curves.json"  # learned from clean flights
CPCE_CALIB = ROOT / "results" / "calibration" / "cpce.json"  # physics noise levels and CUSUM threshold
ESTIMATOR_CALIB = ROOT / "results" / "calibration" / "estimator.json"  # EKF test-ratio thresholds


def _pub(run: Path, name: str) -> bytes:
    return bytes.fromhex((run / f"{name}.pub").read_text())


def detectors(
    side: str,
    run: Path,
    link_curves: Path = LINK_CURVES,
    cpce_calib: Path = CPCE_CALIB,
    estimator_calib: Path = ESTIMATOR_CALIB,
) -> list:
    """Each agent's detector set for a recorded run; learned link, physics and estimator settings if calibrated."""
    if side == "onboard":
        verifier = CmdVerifier(_pub(run, "ground_sign"))
        baseline = load_baseline(BASELINE.with_suffix(".json"), bytes.fromhex(BASELINE.with_suffix(".pub").read_text()))
        onboard = [for_agent("onboard", verifier=verifier), verifier, IntegrityMonitor(baseline, verifier)]
        if cpce_calib.exists():
            onboard.append(Cpce(json.loads(cpce_calib.read_text())))
        if estimator_calib.exists():
            onboard.append(EstimatorMonitor(json.loads(estimator_calib.read_text())))
        return onboard
    curves = load_curves(link_curves) if link_curves.exists() else {}
    rx = CommitRx(_pub(run, "onboard_commit"), **curves.pop("commit", {}))
    return [for_agent("ground"), rx, LinkMonitor(rx, curves=curves or None), ResponseMonitor(rx=rx)]


def evaluate(
    run: Path, link_curves: Path = LINK_CURVES, cpce_calib: Path = CPCE_CALIB, estimator_calib: Path = ESTIMATOR_CALIB
) -> dict:
    labels = json.loads((run / "labels.json").read_text())
    t0 = labels["t0_wall"]
    out = {
        "run_id": labels["run_id"],
        "status": labels["status"],
        "attack": labels["attack"],
        "attack_events": [e for e in labels["events"] if e["event"].startswith("attack")],
        "evidence": [],
        "episodes": [],
        "adapter_unknown": {},
    }
    for side in ("onboard", "ground"):
        ids = Ids(detectors(side, run, link_curves, cpce_calib, estimator_calib))
        run_replay(ids, run / side)
        out["adapter_unknown"][side] = dict(ids.adapter.stats["unknown"])
        for a in ids.alerts:
            for e in a.evidence:
                out["evidence"].append(
                    {
                        "agent": side,
                        "t": round(e.t - t0, 2),
                        "source": e.source,
                        "type": e.evidence_type,
                        "class": e.class_hint,
                        "severity": int(e.severity),
                    }
                )
        for ep in ids.tracker.episodes:
            out["episodes"].append(
                {
                    "agent": side,
                    "class": ep.attack_class,
                    "t_start": round(ep.t_start - t0, 2),
                    "t_end": None if ep.t_end is None else round(ep.t_end - t0, 2),
                    "alerts": len(ep.alerts),
                    "severity": max(int(a.severity) for a in ep.alerts),
                }
            )
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="+", type=Path)
    ap.add_argument("--events", action="store_true", help="print every evidence event")
    a = ap.parse_args()
    for run in a.runs:
        r = evaluate(run)
        att = r["attack"]
        print(
            f"{r['run_id']}: {r['status']}; attack {att['type'] if att else None} "
            f"[{att['start_s'] if att else ''}, {att['end_s'] if att else ''}]"
        )
        for ep in r["episodes"]:
            span = f"{ep['t_start']:>7} .. {ep['t_end']}"
            print(f"   episode {ep['agent']:7s} {ep['class']:24s} {span}  ({ep['alerts']} alerts)")
        if a.events:
            for e in r["evidence"]:
                print("     ", e)


if __name__ == "__main__":
    main()
