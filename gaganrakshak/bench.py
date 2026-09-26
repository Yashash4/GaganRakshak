"""Benchmark: the test-split flight plan and the headline metrics computed from its per-run exports.

    python -m gaganrakshak.bench plan --n 10 --m 20 --out results/bench/test_plan.json
    python -m gaganrakshak.bench fly --n 10 --m 20            # real time, results/raw/test
    python -m gaganrakshak.bench metrics results/runs/test    # -> results/bench/summary.{json,md}

Test seeds start at 5001 and are never used for calibration or tuning; every test plan carries
split "test" (a held-out variant keeps variant "held_out").

Metrics use the per-run exports only (the same JSON an independent verifier reads), scenario time
t = 0 at the takeoff command:
- Detection (headline): an episode of the attack's EXPECTED class, severity MEDIUM or higher,
  starting in [attack_start, attack_end] ("during"). "Detected incl. release" also counts one
  starting up to attack_end + GRACE_S (the attack's end is visible to the IDS). Latency = episode
  start - attack start. The IDS must detect on the expected agent where one is named; the
  baseline has one agent. For GNSS attacks, a gnss_integrity_advisory (LOW) in the same window
  without a detection is "advisory only".
- Secondary detections: MEDIUM+ episodes of any other class starting in [attack_start,
  attack_end + SETTLE_S]; counted per attack type, neither detections nor false alarms.
- False alarms: MEDIUM+ episodes of any class starting in clean flight time: benign flights from
  takeoff to touchdown; attack flights from takeoff to attack start and from attack_end +
  SETTLE_S to touchdown. Rate per clean (airborne) flight-hour with its 95 % one-sided Poisson
  upper bound; advisories (LOW) are counted apart. Episodes before takeoff or after touchdown
  (outside [attack_start, attack_end + SETTLE_S]) are false alarms too; they add to the count, not
  to the hours, and are also listed as ground_phase_false_alarms (distance band "on_ground").
- Splits: attack start before / after the physics engine's longest horizon armed, and distance
  from home at attack start (bands in BANDS_M); false alarms per band use the clean time spent in it.
The same metrics are computed for stock ArduPilot's own indicators (baseline_episodes).
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import re
from collections import defaultdict
from pathlib import Path

import numpy as np

from .estimator import poisson_upper

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "scenarios"
FIRST_SEED = 5001
GRACE_S = 10.0  # an expected-class detection up to this long after the attack ends counts as "at release"
SETTLE_S = 30.0  # after the attack ends, alarms count as false again only after this settling time
BANDS_M = (0.0, 100.0, 200.0, 400.0, math.inf)
GNSS = {"gps_jump", "gps_drift", "gps_drift_naive", "gps_drift_accel"}
EXPECTED = {  # attack type -> (expected class, agent that must raise it or None for either)
    **{t: ("gps_spoofing", "onboard") for t in GNSS},
    "command_injection": ("command_injection", None),
    "telemetry_manipulation": ("telemetry_manipulation", "ground"),
    "fc_impersonation": ("telemetry_manipulation", "ground"),
    "link_flood": ("dos", None),
    "jamming": ("dos", None),
    # drift then jamming (development only): a spoofed far distance must not excuse the jamming.
    # Latency counts from the drift's start, so it includes the jam's delay (jam_after_s).
    "gps_drift_jam": ("dos", None),
    "param_tamper": ("integrity_violation", None),
    "replay": ("replay", None),
}
ATTACKS = (
    "a1_gps_jump",
    "a2_gps_drift",
    "a2n_gps_drift_naive",
    "a3_cmd_injection",
    "a4_telemetry_position",
    "a5_link_flood",
    "a6_param_tamper",
    "a7_replay",
    "a8_fc_impersonation",
    "a9_jamming",
)
RATES_MS = (0.1, 0.25, 0.5, 1.0, 2.0)
ACCELS_MS2 = (0.005, 0.01, 0.02, 0.05, 0.1)
EARLY_START_S = 20.0


# -- plan -------------------------------------------------------------------------------------


def _spec(name: str) -> dict:
    import yaml

    return yaml.safe_load((SCENARIOS / f"{name}.yaml").read_text())


def _plan(spec: dict, seed: int, suffix: str = "") -> dict:
    from .scenario import resolve

    p = resolve(spec, seed)
    p["run_id"] = f"{spec['name']}{suffix}-s{seed}"
    if p["attack"]:
        p["variant"] = "held_out" if p["split"] == "heldout" else "dev"
    p["split"] = "test"
    return p


def plan_test(n: int = 10, m: int = 20, first_seed: int = FIRST_SEED) -> list[dict]:
    """Every attack scenario and held-out variant x n seeds; the a2/a2n drift-rate curve and the
    early-start a2a acceleration curve x n; every benign scenario x m."""
    seeds = range(first_seed, first_seed + n)
    held_out = sorted(p.stem for p in SCENARIOS.glob("a[35]h_*.yaml"))
    plans = [_plan(_spec(s), k) for s in (*ATTACKS, *held_out) for k in seeds]
    for name in ("a2_gps_drift", "a2n_gps_drift_naive"):
        for r in RATES_MS:
            spec = copy.deepcopy(_spec(name))
            spec["attack"]["params"]["rate_ms"] = r
            plans += [_plan(spec, k, f"-r{r}") for k in seeds]
    for a in ACCELS_MS2:
        spec = copy.deepcopy(_spec("a2a_gps_drift_accel"))
        spec["attack"]["params"]["accel_ms2"] = a
        spec["attack"]["start_s"] = EARLY_START_S
        plans += [_plan(spec, k, f"-a{a}-early") for k in seeds]
    benign = sorted(p.stem for p in SCENARIOS.glob("b[1-7]_*.yaml"))
    plans += [_plan(_spec(s), k) for s in benign for k in range(first_seed, first_seed + m)]
    if len({p["run_id"] for p in plans}) != len(plans):
        raise ValueError("duplicate run ids in the test plan")
    return plans


# -- metrics ------------------------------------------------------------------------------------


def band(d: float | None) -> str | None:
    if d is None:
        return None
    for lo, hi in zip(BANDS_M, BANDS_M[1:], strict=False):
        if lo <= d < hi:
            return f"{lo:.0f}-{hi:.0f} m" if hi < math.inf else f">{lo:.0f} m"
    return None


def distance_at(track: list, t: float) -> float | None:
    """Distance of the last track point at or before t (the first one if t precedes the track)."""
    if not track:
        return None
    ts = [x[0] for x in track]
    i = max(0, int(np.searchsorted(ts, t, side="right")) - 1)
    return track[i][1]


def band_time(track: list, t0: float, t1: float) -> dict[str, float]:
    """Seconds spent in each distance band within [t0, t1]; each point holds until the next."""
    out: dict[str, float] = defaultdict(float)
    for k, (t, d) in enumerate(track):
        a, b = max(t, t0), min(track[k + 1][0] if k + 1 < len(track) else t1, t1)
        if b > a:
            out[band(d) or "?"] += b - a
    return out


def clean_intervals(doc: dict) -> list[tuple[float, float]]:
    """Clean flight time: takeoff to touchdown on benign flights; on attack flights takeoff to
    attack start, and attack end + SETTLE_S to touchdown."""
    f = doc["flight_s"]
    if f is None:
        return []
    if not doc["attack"]:
        return [(0.0, f)]
    s, e = doc["attack"]["start_s"], doc["attack"]["end_s"]
    return [iv for iv in ((0.0, min(s, f)), (e + SETTLE_S, f)) if iv[1] > iv[0]]


def phase(doc: dict, t: float) -> str | None:
    """Where an episode starting at t is judged as a possible false alarm: "airborne" (takeoff to
    touchdown), "on_ground" (before takeoff or after touchdown), or None inside [attack_start,
    attack_end + SETTLE_S] on an attack flight."""
    a = doc["attack"]
    if a and a["start_s"] <= t <= a["end_s"] + SETTLE_S:
        return None
    f = doc["flight_s"]
    return "on_ground" if t < 0.0 or (f is not None and t > f) else "airborne"


def group_of(doc: dict) -> str:
    return re.sub(r"-s\d+$", "", doc["run_id"])


def detection(doc: dict, eps: list, agent_check: bool) -> dict:
    a = doc["attack"]
    cls, agent = EXPECTED[a["type"]]
    s, e = a["start_s"], a["end_s"]

    def expected(ep):
        return ep["class"] == cls and ep["severity"] >= 2 and (agent is None or not agent_check or ep["agent"] == agent)

    hits = sorted(ep["t_start"] for ep in eps if expected(ep) and s <= ep["t_start"] <= e + GRACE_S)
    secondary = [ep for ep in eps if ep["severity"] >= 2 and not expected(ep) and s <= ep["t_start"] <= e + SETTLE_S]
    advisory = a["type"] in GNSS and any(
        ep["class"] == "gnss_integrity_advisory" and s <= ep["t_start"] <= e + GRACE_S for ep in eps
    )
    r = {"detected": bool(hits), "during": bool(hits) and hits[0] <= e, "secondary": len(secondary)}
    r["advisory_only"] = advisory and not hits
    r["latency_s"] = round(hits[0] - s, 2) if hits else None
    return r


def _lat(xs: list[float]) -> dict | None:
    if not xs:
        return None
    return {
        "median": round(float(np.median(xs)), 2),
        "p90": round(float(np.percentile(xs, 90)), 2),
        "min": min(xs),
        "max": max(xs),
    }


def _summary(rows: list[dict]) -> dict:
    during = [r["latency_s"] for r in rows if r["during"]]
    incl = [r["latency_s"] for r in rows if r["detected"]]
    return {
        "runs": len(rows),
        "detected_during": len(during),
        "detection_rate_during": round(len(during) / len(rows), 3) if rows else None,
        "detected_incl_release": len(incl),
        "at_release": len(incl) - len(during),
        "missed": len(rows) - len(incl),
        "advisory_only": sum(1 for r in rows if r["advisory_only"]),
        "secondary_episodes": sum(r["secondary"] for r in rows),
        "latency_during_s": _lat(during),
        "latency_incl_release_s": _lat(incl),
    }


def _rate(n: int, hours: float) -> dict:
    return {
        "count": n,
        "clean_hours": round(hours, 3),
        "per_hour": round(n / hours, 3) if hours else None,
        "upper95_per_hour": round(poisson_upper(n, hours), 3) if hours else None,
    }


def score(docs: list[dict], key: str, agent_check: bool) -> dict:
    """Metrics of one tool (``key`` = "episodes" for the IDS, "baseline_episodes" for ArduPilot)."""
    groups, by_arming, by_band = defaultdict(list), defaultdict(list), defaultdict(list)
    fa = adv = 0
    hours = 0.0
    band_s: dict[str, float] = defaultdict(float)
    fa_band: dict[str, int] = defaultdict(int)
    false_alarms, ground = [], []
    for doc in docs:
        eps = doc[key]
        if doc["attack"]:
            r = detection(doc, eps, agent_check)
            s = doc["attack"]["start_s"]
            armed = doc.get("physics", {}).get("armed_s")
            arming = "never armed" if armed is None else ("before arming" if s < armed else "after arming")
            groups[group_of(doc)].append(r)
            by_arming[f"{doc['attack']['type']}, {arming}"].append(r)
            by_band[
                f"{doc['attack']['type']}, {band(distance_at(doc.get('distance_track', []), s)) or 'unknown'}"
            ].append(r)
        track = doc.get("distance_track", [])
        clean = clean_intervals(doc)
        for c0, c1 in clean:
            hours += (c1 - c0) / 3600
            for b, sec in band_time(track, c0, c1).items():
                band_s[b] += sec
        for ep in eps:
            where = phase(doc, ep["t_start"])
            if where is None:
                continue
            if ep["severity"] < 2:
                adv += 1
                continue
            fa += 1
            item = {"run": doc["run_id"], **{k: ep.get(k) for k in ("agent", "class", "t_start", "evidence_types")}}
            false_alarms.append(item)
            if where == "on_ground":
                ground.append(item)
                fa_band["on_ground"] += 1
            else:
                fa_band[band(distance_at(track, ep["t_start"])) or "?"] += 1
    return {
        "detection": {g: _summary(v) for g, v in sorted(groups.items())},
        "detection_by_arming": {g: _summary(v) for g, v in sorted(by_arming.items())},
        "detection_by_distance": {g: _summary(v) for g, v in sorted(by_band.items())},
        "false_alarms": {
            **_rate(fa, hours),
            "advisories": adv,
            "by_distance": {
                **{b: _rate(fa_band.get(b, 0), sec / 3600) for b, sec in sorted(band_s.items())},
                "on_ground": _rate(fa_band.get("on_ground", 0), 0.0),
            },
            "ground_phase_false_alarms": {"count": len(ground), "list": ground},
            "list": false_alarms,
        },
    }


def metrics(export_dir: Path) -> dict:
    docs = [json.loads(f.read_text()) for f in sorted(export_dir.rglob("*.json"))]
    docs = [d for d in docs if d["status"] == "ok"]
    if any(d["split"] != "test" for d in docs):
        raise ValueError("metrics are computed on test-split exports only")
    return {
        "runs": len(docs),
        "attack_runs": sum(1 for d in docs if d["attack"]),
        "benign_runs": sum(1 for d in docs if not d["attack"]),
        "calibration": sorted({json.dumps(d["calibration"], sort_keys=True) for d in docs}),
        "grace_s": GRACE_S,
        "settle_s": SETTLE_S,
        "ids": score(docs, "episodes", agent_check=True),
        "baseline": score(docs, "baseline_episodes", agent_check=False),
    }


def markdown(m: dict) -> str:
    def lat(s):
        x = s["latency_during_s"]
        return "" if not x else f"{x['median']} / {x['p90']}"

    out = [
        f"# Benchmark (SITL, test split)\n\n{m['runs']} runs ({m['attack_runs']} attack, {m['benign_runs']} benign). "
        f"Detected = expected class, MEDIUM or higher, starting during the attack; incl. release = up to "
        f"{m['grace_s']:g} s after its end. False alarms exclude attack start to attack end + {m['settle_s']:g} s. "
        "Latency (detections during the attack): median / p90, s.\n",
        "## Detection\n",
        "| scenario | runs | IDS during | IDS incl. release | advisory only | secondary | IDS latency "
        "| ArduPilot during | ArduPilot incl. release | ArduPilot latency |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for g, s in m["ids"]["detection"].items():
        b = m["baseline"]["detection"][g]
        out.append(
            f"| {g} | {s['runs']} | {s['detected_during']} | {s['detected_incl_release']} | {s['advisory_only']} "
            f"| {s['secondary_episodes']} | {lat(s)} | {b['detected_during']} | {b['detected_incl_release']} "
            f"| {lat(b)} |"
        )
    for title, k in (
        ("By physics arming at attack start", "detection_by_arming"),
        ("By distance at attack start", "detection_by_distance"),
    ):
        out += [
            f"\n## {title}\n",
            "| attack type / split | runs | IDS during | ArduPilot during |",
            "|---|---|---|---|",
        ]
        for g, s in m["ids"][k].items():
            out.append(f"| {g} | {s['runs']} | {s['detected_during']} | {m['baseline'][k][g]['detected_during']} |")
    out += [
        "\n## False alarms (MEDIUM+, clean flight time)\n",
        "| | clean hours | false alarms | of which on ground | per hour | 95 % upper bound | advisories |",
        "|---|---|---|---|---|---|---|",
    ]
    for name in ("ids", "baseline"):
        f = m[name]["false_alarms"]
        label = "IDS" if name == "ids" else "ArduPilot"
        g = f["ground_phase_false_alarms"]["count"]
        cells = [label, f["clean_hours"], f["count"], g, f["per_hour"], f["upper95_per_hour"], f["advisories"]]
        out.append("| " + " | ".join(str(c) for c in cells) + " |")
    out += [
        "\n### IDS false alarms by distance\n",
        "| band | clean hours | false alarms | per hour | 95 % upper bound |",
        "|---|---|---|---|---|",
    ]
    for b, f in m["ids"]["false_alarms"]["by_distance"].items():
        out.append(f"| {b} | {f['clean_hours']} | {f['count']} | {f['per_hour']} | {f['upper95_per_hour']} |")
    return "\n".join(out) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("plan", "fly"):
        p = sub.add_parser(name)
        p.add_argument("--n", type=int, default=10, help="seeds per attack scenario and per rate")
        p.add_argument("--m", type=int, default=20, help="seeds per benign scenario")
        p.add_argument("--out", type=Path, default=None)
        p.add_argument("--workers", type=int, default=16)
        p.add_argument("--first-instance", type=int, default=20)
    p = sub.add_parser("metrics")
    p.add_argument("export_dir", type=Path)
    p.add_argument("--out", type=Path, default=ROOT / "results" / "bench")
    a = ap.parse_args()
    if a.cmd == "metrics":
        m = metrics(a.export_dir)
        a.out.mkdir(parents=True, exist_ok=True)
        (a.out / "summary.json").write_text(json.dumps(m, indent=1))
        (a.out / "summary.md").write_text(markdown(m))
        print(markdown(m))
        return
    plans = plan_test(a.n, a.m)
    if a.cmd == "plan":
        out = a.out or ROOT / "results" / "bench" / "test_plan.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(plans, indent=1))
        print(f"{len(plans)} test runs -> {out}")
        return
    from .scenario import run_many

    for run_id, status in run_many(plans, a.out or ROOT / "results" / "raw" / "test", a.workers, a.first_instance):
        print(run_id, status)


if __name__ == "__main__":
    main()
