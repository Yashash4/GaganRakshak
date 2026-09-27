"""Flight plans for the second-GNSS-reference extension (kept apart from the frozen base benchmark).

Every plan flies with a second, reference-only receiver (``gnss2``); the autopilot and the attacker
models are the base ones (the attacker spoofs the navigation receiver only).

- smoke: a handful of development flights (seeds 901+) to check the chain end to end
- calibration: B1-B7 on calibration seeds 7001+ (the new statistic's threshold is learned here only)
- test: pre-registered in configs/bench_dual.json -- the a2 and a2n drift-rate curves
  (0.25, 0.5, 1.0, 2.0 m/s) and B1-B7, seeds 6001-6010. The a2a acceleration curve is not
  evaluated in the extension.

    python -m gaganrakshak.dual_bench plan            # writes configs/bench_dual.json (commit it first)
    python -m gaganrakshak.dual_bench fly smoke|calibration|test
"""

from __future__ import annotations

import argparse
import copy
import json

from .bench import ROOT, SCENARIOS, _plan, _spec, check_unflown, manifest

GNSS2 = {"sigma_m": 2.1, "tau_s": 60.0}  # the same receiver class as the navigation receiver
RATES_MS = (0.25, 0.5, 1.0, 2.0)
TEST_SEEDS = range(6001, 6011)
CALIBRATION_SEEDS = range(7001, 7017)
SMOKE_SEED = 901
MANIFEST = ROOT / "configs" / "bench_dual.json"
RAW = ROOT / "results" / "raw" / "dual"


def _dual(spec: dict) -> dict:
    spec = copy.deepcopy(spec)
    spec["gnss2"] = dict(GNSS2)
    return spec


def _benign() -> list[str]:
    return sorted(p.stem for p in SCENARIOS.glob("b[1-7]_*.yaml"))


def plan_test() -> list[dict]:
    plans = []
    for name in ("a2_gps_drift", "a2n_gps_drift_naive"):
        for r in RATES_MS:
            spec = _dual(_spec(name))
            spec["attack"]["params"]["rate_ms"] = r
            plans += [_plan(spec, k, f"-r{r}-g2") for k in TEST_SEEDS]
    plans += [_plan(_dual(_spec(s)), k, "-g2") for s in _benign() for k in TEST_SEEDS]
    return plans


def plan_calibration() -> list[dict]:
    plans = [_plan(_dual(_spec(s)), k, "-g2") for s in _benign() for k in CALIBRATION_SEEDS]
    for p in plans:
        p["split"] = "calibration"
    return plans


def plan_smoke() -> list[dict]:
    plans = [_plan(_dual(_spec("b1_calm")), SMOKE_SEED, "-g2")]
    for name, r in (("a2_gps_drift", 0.5), ("a2n_gps_drift_naive", 2.0)):
        spec = _dual(_spec(name))
        spec["attack"]["params"]["rate_ms"] = r
        plans.append(_plan(spec, SMOKE_SEED, f"-r{r}-g2"))
    plans.append(_plan(_dual(_spec("a1_gps_jump")), SMOKE_SEED, "-g2"))
    for p in plans:
        p["split"] = "development"
    return plans


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("plan")
    f = sub.add_parser("fly")
    f.add_argument("which", choices=("smoke", "calibration", "test"))
    f.add_argument("--workers", type=int, default=16)
    f.add_argument("--first-instance", type=int, default=20)
    a = ap.parse_args()
    test = plan_test()
    m = manifest(test)
    if a.cmd == "plan":
        MANIFEST.write_text(json.dumps(m, indent=1) + "\n")
        print(f"{len(test)} test runs -> {MANIFEST}")
        return
    plans = {"smoke": plan_smoke, "calibration": plan_calibration, "test": lambda: test}[a.which]()
    raw = RAW / a.which
    if a.which == "test":
        if not MANIFEST.exists() or json.loads(MANIFEST.read_text()) != json.loads(json.dumps(m)):
            raise SystemExit(f"the plan differs from the committed manifest {MANIFEST}")
        check_unflown(plans, ROOT / "results" / "runs_dual", raw=raw)
    from .scenario import run_many

    for run_id, status in run_many(plans, raw, a.workers, a.first_instance):
        print(run_id, status, flush=True)


if __name__ == "__main__":
    main()
