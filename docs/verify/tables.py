"""Markdown tables for the report, computed only by the independent verifier from exported runs.
Usage: python report/verify/tables.py code/results/runs/test [code/results/runs/test_nocrypto]"""

import json
import sys
from collections import Counter
from pathlib import Path

from verify import check_calibration, verify


def fmt(x) -> str:
    return "-" if x is None else f"{x:.1f}"


def runs_in(d: Path) -> list[dict]:
    return [json.loads(p.read_text()) for p in sorted(d.rglob("*.json"))]


def table(name: str, runs: list[dict]) -> None:
    r = verify(runs)
    print(f"## {name}: {len(runs)} runs, calibration problems: {check_calibration(runs) or 'none'}\n")
    print(
        f"False alarms: {r['false_alarms']} in {r['clean_hours']} clean airborne h = {r['fa_per_clean_hour']}/h "
        f"(95 % UB {r['fa_per_clean_hour_upper95']}); on ground {r['ground_phase_false_alarms']}; "
        f"advisories in clean time {r['advisories_in_clean_time']}; set-aside artefacts {len(r['artefact_episodes'])}\n"
    )
    by = Counter(rid.rsplit("-s", 1)[0] for rid, _, _ in r["false_alarm_detail"])
    print("| scenario | false alarms |\n|---|---|")
    for k, n in sorted(by.items()):
        print(f"| {k} | {n} |")
    print(
        "\n| scenario | runs | detected during | incl. release | advisory only | p50 s | p95 s |\n|---|---|---|---|---|---|---|"  # noqa: E501
    )
    for g, v in r["per_scenario"].items():
        print(
            f"| {g} | {v['runs']} | {v['detected_during_attack']} | {v['detected']} | {v['advisory_only']} "
            f"| {fmt(v['latency_p50_s'])} | {fmt(v['latency_p95_s'])} |"
        )
    print("\nSecondary detections:", r["secondary_detections"], "\n")


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        table(Path(arg).name, runs_in(Path(arg)))
