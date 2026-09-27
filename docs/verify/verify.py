"""Independent verification of GaganRakshak's headline metrics (WIN, D-022).

Recomputes, from the raw per-run exports only (code/results/runs/<split>/<run_id>.json),
the numbers the report quotes, using the spec's definitions — deliberately NOT importing
any gaganrakshak code, so a bug or convenient choice in the project's own metrics
pipeline cannot hide here.

Definitions (spec §5):
- Detection: an attack run is detected if an episode of the expected class starts in
  [attack_start, attack_end + GRACE_S]. Latency = episode start − attack start. Reported
  separately: detection DURING the attack (episode starts before attack_end) — an alarm
  that only comes when the spoofer stops ("at release") must not inflate the headline.
- False alarm: one episode (any class) in a benign run; in attack runs, an episode that starts
  before attack_start or more than SETTLE_S after attack_end. Other-class episodes raised
  while the attack is active are reported as secondary detections, not false alarms.
- FPR is reported per flight-hour of airborne time, with an exact Poisson 95 % upper bound, and
  per CLEAN hour: benign flights plus the pre-attack part of attack flights (the headline
  denominator — airborne time while no attack is active).

    python report/verify/verify.py code/results/runs --split test [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path

GRACE_S = 10.0
SETTLE_S = 30.0  # after attack_end, effects of the attack may still raise alarms
ALARM_MIN_SEVERITY = 2  # MEDIUM+: alarms. LOW episodes are advisories, counted separately.

# Attack type (scenario) -> acceptable alarm classes. Written from the spec's threat
# catalogue, independently of the project's own mapping.
EXPECTED = {
    "gps_jump": {"gps_spoofing"},
    "gps_drift": {"gps_spoofing"},
    "gps_drift_naive": {"gps_spoofing"},
    "gps_drift_accel": {"gps_spoofing"},
    "gps_drift_jam": {"dos"},
    "command_injection": {"command_injection"},
    "telemetry_manipulation": {"telemetry_manipulation"},
    "link_flood": {"dos"},
    "param_tamper": {"integrity", "integrity_violation"},
    "replay": {"replay", "command_injection"},
    "fc_impersonation": {"mavlink_anomaly", "telemetry_manipulation"},
    "jamming": {"dos"},
}


# Agent that must raise the expected class (the design claim): GNSS onboard; link-content
# attacks on the ground; others either agent.
EXPECTED_AGENT = {
    "gps_jump": "onboard",
    "gps_drift": "onboard",
    "gps_drift_naive": "onboard",
    "gps_drift_accel": "onboard",
    "telemetry_manipulation": "ground",
    "fc_impersonation": "ground",
}


def poisson_upper(k: int, t_hours: float, conf: float = 0.95) -> float:
    """Exact one-sided upper confidence bound on a Poisson rate (events per hour)."""
    if t_hours <= 0:
        return math.inf

    # find lambda with P(X <= k; lambda) = 1 - conf by bisection (no scipy needed)
    def cdf(lam: float) -> float:
        term = total = math.exp(-lam)
        for i in range(1, k + 1):
            term *= lam / i
            total += term
        return total

    lo, hi = 0.0, max(10.0, 10.0 * (k + 1))
    for _ in range(200):
        mid = (lo + hi) / 2
        if cdf(mid) > 1 - conf:
            lo = mid
        else:
            hi = mid
    return hi / t_hours


def _attack_window(run: dict) -> tuple[float | None, float | None]:
    ts = {e["event"]: e["t"] for e in run.get("events", []) if e["event"] in ("attack_start", "attack_end")}
    return ts.get("attack_start"), ts.get("attack_end")


REQUIRED_ARTEFACTS = ("cpce.json", "link_curves.json")


def check_calibration(runs: list[dict]) -> list[str]:
    """Every run must record the hash of every required calibration artefact, and all runs in
    the set must share the same hashes — otherwise the numbers mix calibrations or ran on
    silent defaults."""
    problems, seen = [], {}
    for r in runs:
        cal = r.get("calibration") or {}
        missing = [a for a in REQUIRED_ARTEFACTS if a not in cal]
        if missing:
            problems.append(f"{r.get('run_id')}: missing calibration {missing}")
        for a, h in cal.items():
            seen.setdefault(a, set()).add(h)
    problems += [f"{a}: {len(hs)} different hashes across runs" for a, hs in seen.items() if len(hs) > 1]
    # every run in a split must be scored by one detector code version (exports without the field predate it)
    ev = {r.get("evaluated_with") for r in runs if r.get("evaluated_with")}
    if len(ev) > 1:
        problems.append(f"evaluated_with: {len(ev)} different detector code versions {sorted(ev)}")
    problems += [f"evaluated_with {v}: dirty tree" for v in ev if "dirty" in str(v)]
    # the crypto-off ablation replay must never be mixed into a normal split
    if len({r.get("crypto", True) for r in runs}) > 1:
        problems.append("crypto: normal and crypto-off (ablation) replays mixed in one split")
    return problems


def verify(runs: list[dict]) -> dict:
    per_type = defaultdict(lambda: {"runs": 0, "detected": 0, "during": 0, "advisory_only": 0, "latencies": []})
    per_group = defaultdict(lambda: {"runs": 0, "detected": 0, "during": 0, "advisory_only": 0, "latencies": []})
    fa, flight_s, benign_runs = 0, 0.0, 0
    fa_detail = []
    adv = 0
    artefacts: list = []
    bad_marks: list = []
    clean_s = 0.0
    secondary: dict = defaultdict(int)
    ground_fa = 0
    clean_adv = 0  # LOW advisories outside any attack's influence (same rule as false alarms)  # false alarms before takeoff / after touchdown (counted — the operator sees them)  # airborne time with no attack active: benign runs + attack runs before attack_start  # noqa: E501
    no_flight = []
    for r in runs:
        if r.get("status") != "ok":
            continue
        if r.get("flight_s") is None:
            no_flight.append(r["run_id"])
        flight_s += float(r.get("flight_s") or 0.0)
        raw_eps = r.get("episodes", [])

        # Episodes the export marks as a documented artefact (e.g. old signature sizing on
        # recordings provably flown before the fix) are listed apart, never silently dropped.
        # A mark is honoured only if the rule holds independently: run provably flown before the
        # sizing fix and the episode's only evidence is unsigned commands. Any other mark is
        # reported as bad and the episode counts normally.
        def _ok(e):
            return (
                e.get("artefact") == "old_sizing"
                and r.get("flown_at") == "before-b747b3e"  # noqa: B023
                and "unsigned_command" in (e.get("evidence_types") or [])
                and set(e["evidence_types"]) <= {"unsigned_command", "unsafe_command"}
                and bool(e.get("matched_uplink"))
            )  # every received command frame matched a GCS-sent frame

        artefacts += [
            (r["run_id"], e["artefact"], e["class"], e["t_start"]) for e in raw_eps if e.get("artefact") and _ok(e)
        ]
        bad_marks += [(r["run_id"], e["class"], e["t_start"]) for e in raw_eps if e.get("artefact") and not _ok(e)]
        all_eps = [e for e in raw_eps if not _ok(e)]
        eps = [e for e in all_eps if e.get("severity", ALARM_MIN_SEVERITY) >= ALARM_MIN_SEVERITY]
        adv += len(all_eps) - len(eps)
        lows = [e for e in all_eps if e.get("severity", ALARM_MIN_SEVERITY) < ALARM_MIN_SEVERITY]
        att = r.get("attack")
        if not att:
            clean_adv += len(lows)
            flight = float(r.get("flight_s") or 0.0)
            clean_s += flight
            benign_runs += 1
            fa += len(eps)
            ground_fa += sum(1 for e in eps if e["t_start"] < 0 or e["t_start"] > flight)
            fa_detail += [(r["run_id"], e["class"], e["t_start"]) for e in eps]
            continue
        typ = att["type"]
        exp = EXPECTED.get(typ)
        if exp is None:
            raise ValueError(f"{r['run_id']}: attack type {typ!r} has no expected classes defined")
        start, end = _attack_window(r)
        if start is None and att.get("start_s") is not None:
            start, end = att["start_s"], att.get("end_s")
        if start is None:
            raise ValueError(f"{r['run_id']}: attack run without attack_start event")
        flight = float(r.get("flight_s") or 0.0)
        end = end if end is not None else math.inf
        clean_adv += sum(1 for e in lows if e["t_start"] < start or e["t_start"] > end + SETTLE_S)
        clean_s += max(0.0, min(start, flight)) + max(0.0, flight - (end + SETTLE_S))  # t=0 at takeoff
        agent = EXPECTED_AGENT.get(typ)
        hits = [
            e
            for e in eps
            if e["class"] in exp
            and (agent is None or e.get("agent") == agent)
            and start <= e["t_start"] <= end + GRACE_S
        ]
        adv_hit = [
            e
            for e in all_eps
            if e.get("severity", 2) < ALARM_MIN_SEVERITY
            and "gnss" in e["class"]
            and start <= e["t_start"] <= end + GRACE_S
        ]
        # per attack type, and per scenario (far / held-out apart) with the drift rate when set
        prm = (r.get("attack") or {}).get("params") or {}
        rate = next((f"@{k}={prm[k]:g}" for k in ("rate_ms", "accel_ms2") if isinstance(prm.get(k), (int, float))), "")
        for pt in (per_type[typ], per_group[f"{r.get('scenario', typ)}{rate}"]):
            pt["runs"] += 1
            if not hits and adv_hit:
                pt["advisory_only"] += 1
            if hits:
                pt["detected"] += 1
                if any(e["t_start"] <= end for e in hits):
                    pt["during"] += 1  # alarm while the attack was still active (not only at release)
                pt["latencies"].append(min(e["t_start"] for e in hits) - start)
        for e in eps:
            if e in hits:
                continue
            if e["t_start"] < start or e["t_start"] > end + SETTLE_S:
                fa += 1  # outside the attack's influence: a false alarm
                fa_detail.append((r["run_id"], e["class"], e["t_start"]))
                if e["t_start"] < 0 or e["t_start"] > flight:
                    ground_fa += 1
            elif e["class"] in exp and (agent is None or e.get("agent") == agent) and e["t_start"] > end + GRACE_S:
                pass  # late expected-class episode: neither a detection nor a false alarm
            else:
                secondary[(typ, e["class"])] += 1  # other class (or wrong agent) raised by the same attack
    hours = flight_s / 3600.0

    def pct(xs: list[float], q: float) -> float | None:
        if not xs:
            return None
        xs = sorted(xs)
        return xs[min(len(xs) - 1, int(math.ceil(q * len(xs))) - 1)]

    return {
        "flight_hours": round(hours, 3),
        "benign_runs": benign_runs,
        "false_alarms": fa,
        "clean_hours": round(clean_s / 3600.0, 3),
        "fa_per_clean_hour": round(fa / (clean_s / 3600.0), 4) if clean_s else None,
        "fa_per_clean_hour_upper95": round(poisson_upper(fa, clean_s / 3600.0), 4) if clean_s else None,
        "fa_per_hour": round(fa / hours, 4) if hours else None,
        "fa_per_hour_upper95": round(poisson_upper(fa, hours), 4) if hours else None,
        "false_alarm_detail": fa_detail,
        "artefact_episodes": artefacts,
        "rejected_artefact_marks": bad_marks,
        "ground_phase_false_alarms": ground_fa,
        "secondary_detections": {f"{a}->{c}": n for (a, c), n in sorted(secondary.items())},
        "advisories_all_runs": adv,
        "advisories_in_clean_time": clean_adv,
        "advisories_per_hour": round(adv / hours, 4) if hours else None,
        "runs_without_flight_time": no_flight,
        "per_attack": {
            t: {
                "runs": v["runs"],
                "detected": v["detected"],
                "detection_rate": round(v["detected"] / v["runs"], 4) if v["runs"] else None,
                "detected_during_attack": v["during"],
                "advisory_only": v["advisory_only"],
                "detection_rate_during_attack": round(v["during"] / v["runs"], 4) if v["runs"] else None,
                "latency_p50_s": pct(v["latencies"], 0.5),
                "latency_p95_s": pct(v["latencies"], 0.95),
            }
            for t, v in sorted(per_type.items())
        },
        "per_scenario": {
            g: {
                "runs": v["runs"],
                "detected": v["detected"],
                "detected_during_attack": v["during"],
                "advisory_only": v["advisory_only"],
                "latency_p50_s": pct(v["latencies"], 0.5),
                "latency_p95_s": pct(v["latencies"], 0.95),
            }
            for g, v in sorted(per_group.items())
        },
    }


def load(root: Path, split: str | None) -> list[dict]:
    paths = sorted((root / split).rglob("*.json")) if split else sorted(root.rglob("*.json"))
    return [json.loads(p.read_text()) for p in paths]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", type=Path)
    ap.add_argument("--split", default="test")
    ap.add_argument("--json", type=Path)
    a = ap.parse_args()
    runs = load(a.root, a.split)
    res = verify(runs)
    res["calibration_problems"] = check_calibration(runs)
    print(json.dumps(res, indent=2))
    if a.json:
        a.json.write_text(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
