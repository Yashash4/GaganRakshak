"""Three rows for the second-GNSS-reference extension, all on the same extension test flights:

1. base  -- the frozen single-receiver IDS (exports without --dual-gnss)
2. dual  -- the reference-disagreement statistic alone, at its learned threshold
3. both  -- the base IDS plus the new statistic (exports with --dual-gnss)

Detection per scenario group (during the attack / during or at release) and the MEASURED false
alarms (MEDIUM+, clean flight time, 95 % upper bound), scored exactly as the base benchmark.

    python tools/dual_rows.py results/runs_dual_base/test results/runs_dual/test --out results/bench_dual
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from gaganrakshak import bench


def load(d: Path) -> list[dict]:
    docs = [json.loads(f.read_text()) for f in sorted(d.rglob("*.json"))]
    return [x for x in docs if x["status"] == "ok"]


def dual_only(docs: list[dict]) -> list[dict]:
    """The same flights with only the new statistic's evidence as episodes."""
    out = []
    for d in docs:
        eps = [
            {
                "agent": "onboard",
                "class": "gps_spoofing",
                "severity": 2,
                "t_start": t,
                "t_end": t,
                "evidence_types": ["gnss_reference_disagreement"],
            }
            for t in d["dual_gnss_evidence"]
        ]
        out.append({**d, "episodes": eps})
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base", type=Path, help="exports of the extension test flights without --dual-gnss")
    ap.add_argument("dual", type=Path, help="exports of the same flights with --dual-gnss")
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    base, both = load(a.base), load(a.dual)
    if sorted(d["run_id"] for d in base) != sorted(d["run_id"] for d in both):
        raise SystemExit("the two export sets do not hold the same flights")
    rows = {
        "base single-receiver IDS": bench.score(base, "episodes", agent_check=True),
        "second reference alone": bench.score(dual_only(both), "episodes", agent_check=False),
        "base + second reference": bench.score(both, "episodes", agent_check=True),
        "stock ArduPilot (with the second receiver present)": bench.score(both, "baseline_episodes", agent_check=False),
    }
    groups = sorted(next(iter(rows.values()))["detection"])
    md = ["## Detection (runs detected during the attack / during or at release)", ""]
    md.append("| scenario | runs | " + " | ".join(rows) + " |")
    md.append("|---|---|" + "---|" * len(rows))
    for g in groups:
        cells = [
            f"{r['detection'][g]['detected_during']} / {r['detection'][g]['detected_incl_release']}"
            for r in rows.values()
        ]
        md.append(f"| {g} | {next(iter(rows.values()))['detection'][g]['runs']} | " + " | ".join(cells) + " |")
    md += [
        "",
        "## False alarms (MEDIUM+, clean flight time; measured)",
        "",
        "| row | clean hours | false alarms | per hour | 95 % upper bound |",
        "|---|---|---|---|---|",
    ]
    for name, r in rows.items():
        f = r["false_alarms"]
        md.append(f"| {name} | {f['clean_hours']} | {f['count']} | {f['per_hour']} | {f['upper95_per_hour']} |")
    md += ["", "Not evaluated in the extension: the a2a accelerating-drift curve."]
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "summary.json").write_text(json.dumps(rows, indent=1))
    (a.out / "summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
