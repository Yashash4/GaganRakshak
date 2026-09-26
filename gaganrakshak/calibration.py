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
    "inertial_trend",
    "estimator_innovation_high",
}
# Link-loss corroboration (class dos, e.g. a signature lost on a fading link) and physics advisories
# are consequences of the statistics being calibrated, not anomalies of the flight.
CALIBRATED_CLASSES = {"dos", "gnss_integrity_advisory"}


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

        # judged without any earlier calibration: a stale artefact must not decide what is clean
        ev = [
            e
            for e in evaluate(run, uncalibrated=True)["evidence"]
            if e["type"] not in CALIBRATED_EVIDENCE and e["class"] not in CALIBRATED_CLASSES
        ]
        # A genuine command whose signature copies were all lost in a fade: the radio behaviour is
        # clean, and these flights are the deepest fades the link bands must learn. The evidence is
        # not a sign of an unclean flight, so it is ignored here (and listed by calibrate_all).
        unsigned = [e for e in ev if e["type"] == "unsigned_command"]
        # an unsafe command (e.g. the operator's disarm) judged so only because its own signatures
        # were lost the same way (unsigned within the second before) is the same fade loss
        lost = [e["t"] for e in unsigned]
        ev = [
            e
            for e in ev
            if e["type"] != "unsigned_command"
            and not (e["type"] == "unsafe_command" and any(0.0 <= e["t"] - t <= 1.0 for t in lost))
        ]
        if ev:
            return False, f"IDS evidence: {sorted({(e['agent'], e['type']) for e in ev})}"
        if unsigned:
            return True, f"ok; ignored unsigned_command x{len(unsigned)}"
    return True, "ok"


def select(
    runs: list[Path],
    check_ids: bool = True,
    workers: int = 16,
    skipped: list | None = None,
    ignored: list | None = None,
) -> list[Path]:
    """The usable calibration runs; every decision is printed with its reason (and the rejected
    ones appended to ``skipped`` as {run, reason})."""
    from concurrent.futures import ProcessPoolExecutor

    with ProcessPoolExecutor(workers) as ex:
        verdicts = list(ex.map(usable, runs, [check_ids] * len(runs)))
    keep = []
    for r, (ok, why) in zip(runs, verdicts, strict=True):
        print(f"calibration {'use ' if ok else 'SKIP'} {r.name}: {why}")
        if ok:
            keep.append(r)
            if ignored is not None and why != "ok":
                ignored.append({"run": f"{r.parent.name}/{r.name}", "note": why})
        elif skipped is not None:
            skipped.append({"run": f"{r.parent.name}/{r.name}", "reason": why})
    return keep


# -- one entry point for every calibration artefact -------------------------------------------

# One false-alarm budget for the whole system, split equally over the statistics that can raise an
# alarm (MEDIUM or HIGH) on a clean flight; advisories (LOW) have their own budget, split the same way.
ALARM_STATISTICS = ("excess_loss", "telemetry_gap", "selective_commit_loss", "commit_timeout", "gps_spoofing")
ADVISORY_STATISTICS = ("gnss_inertial_inconsistency", "inertial_trend", "estimator_innovation_high")


def _count(args) -> tuple[dict, dict]:
    """On one clean flight replayed through the calibrated IDS: evidence onsets per type, and
    MEDIUM+ alarm episodes per class (every detector, budgeted or rule-based)."""
    run, out_dir = args
    from .evaluate import evaluate

    r = evaluate(
        run,
        link_curves=out_dir / "link_curves.json",
        cpce_calib=out_dir / "cpce.json",
        estimator_calib=out_dir / "estimator.json",
    )
    by_type: dict = {}
    for e in r["evidence"]:
        by_type[e["type"]] = by_type.get(e["type"], 0) + 1
    alarms: dict = {}
    for ep in r["episodes"]:
        if ep["severity"] >= 2:
            # signature copies all lost in a fade, recorded with the earlier sizing: counted apart
            types = set(ep.get("evidence_types") or [])
            lost = "unsigned_command" in types and types <= {"unsigned_command", "unsafe_command"}
            key = "unsigned_command_old_sizing" if lost else ep["class"]
            alarms[key] = alarms.get(key, 0) + 1
    return by_type, alarms


def airborne_hours(runs: list[Path]) -> float:
    """Takeoff to touchdown (or end) summed over the runs: every false-alarm rate is per airborne hour."""
    total = 0.0
    for r in runs:
        ev = {e["event"]: e["t"] for e in json.loads((r / "labels.json").read_text())["events"]}
        total += max(0.0, ev.get("touchdown", ev.get("end", 0.0)) - ev.get("takeoff", 0.0))
    return total / 3600


def calibrate_all(
    runs: list[Path], out_dir: Path, alarm_budget: float = 1.0, advisory_budget: float = 1.0, workers: int = 16
) -> dict:
    """Guard the runs once, learn every artefact with its share of the budgets, then replay the
    calibration flights through the calibrated IDS and record the in-sample false onsets."""
    from concurrent.futures import ProcessPoolExecutor

    from . import cpce, estimator, link_monitor

    skipped: list[dict] = []
    ignored: list[dict] = []
    runs = select(runs, workers=workers, skipped=skipped, ignored=ignored)
    alarm_share = alarm_budget / len(ALARM_STATISTICS)
    advisory_share = advisory_budget / len(ADVISORY_STATISTICS)
    budget = {
        "alarm_budget_per_hour": alarm_budget,
        "alarm_statistics": list(ALARM_STATISTICS),
        "advisory_budget_per_hour": advisory_budget,
        "advisory_statistics": list(ADVISORY_STATISTICS),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    hours = airborne_hours(runs)
    curves = link_monitor.calibrate(runs, alarm_share, guarded=True, hours=hours)
    link_monitor.save_curves(out_dir / "link_curves.json", curves)
    phys = cpce.calibrate(runs, advisory_share, workers=workers, hours=hours)
    phys["meta"].update(source="clean SITL calibration flights (guard-selected)", system_budget=budget)
    (out_dir / "cpce.json").write_text(json.dumps(phys, indent=1) + "\n")
    with ProcessPoolExecutor(workers) as ex:
        series = list(ex.map(estimator.extract, runs))
    est = estimator.learn(series, advisory_share, hours=hours)
    est["meta"].update(runs=[r.name for r in runs], source="clean SITL calibration flights (guard-selected)")
    (out_dir / "estimator.json").write_text(json.dumps(est, indent=1) + "\n")
    with ProcessPoolExecutor(workers) as ex:
        per_run = list(ex.map(_count, [(r, out_dir) for r in runs]))
    counts: dict = {}
    alarm_classes: dict = {}
    for by_type, by_class in per_run:
        for k, v in by_type.items():
            counts[k] = counts.get(k, 0) + v
        for k, v in by_class.items():
            alarm_classes[k] = alarm_classes.get(k, 0) + v
    # the whole system: every MEDIUM+ episode, any detector (old-sizing signature losses apart)
    alarms = sum(v for k, v in alarm_classes.items() if k != "unsigned_command_old_sizing")
    advisories = sum(counts.get(k, 0) for k in ADVISORY_STATISTICS)
    summary = {
        **budget,
        "runs": len(runs),
        "hours": hours,
        "evidence_onsets_by_type": counts,
        "alarm_episodes_by_class": alarm_classes,
        "alarms_per_hour": round(alarms / hours, 3),
        "alarms_upper95_per_hour": round(estimator.poisson_upper(alarms, hours), 3),
        "advisories_per_hour": round(advisories / hours, 3),
        "advisories_upper95_per_hour": round(estimator.poisson_upper(advisories, hours), 3),
        # clean flights the guard rejected: their alarms are false alarms the in-sample rate above
        # cannot contain, so they are listed here
        "guard_skipped": skipped,
        # kept for learning (the deepest clean fades): genuine commands whose signature copies were all
        # lost; recorded with the earlier signature sizing (2 copies), so the signature layer's
        # false-alarm rate is measured on flights with the current sizing instead
        "guard_ignored_unsigned_command": ignored,
    }
    (out_dir / "calibration_summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    return summary


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Learn every calibration artefact from clean flights.")
    ap.add_argument("runs", nargs="+", type=Path, help="clean calibration run directories")
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parent.parent / "results" / "calibration")
    ap.add_argument("--alarm-budget", type=float, default=1.0, help="false alarms per flight-hour, whole system")
    ap.add_argument("--advisory-budget", type=float, default=1.0, help="false advisories per flight-hour")
    ap.add_argument("--workers", type=int, default=16)
    a = ap.parse_args()
    runs = [r for r in a.runs if (r / "labels.json").exists()]
    print(json.dumps(calibrate_all(runs, a.out, a.alarm_budget, a.advisory_budget, a.workers), indent=1))


if __name__ == "__main__":
    main()
