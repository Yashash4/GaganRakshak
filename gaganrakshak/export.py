"""Per-run export for independent verification: one small JSON per recorded run with the
ground truth and the IDS's final output, and no computed metrics.

    python -m gaganrakshak.export --split validation --raw-root results/raw results/raw/val2/*
    python -m gaganrakshak.export --split calibration --guard --raw-root results/raw results/raw/calib3/*
writes results/runs/<split>/<source>.json (source = the run's path under --raw-root, so runs of
the same scenario and seed from different batches stay apart; else the run id) with: run_id,
source, flown_at (the code version the run was flown with, see flown_at), evaluated_with (the
commit of the code that evaluated it; exports under results/ are refused from uncommitted code),
calibration (the calibration files the IDS used, with their git blob hashes), scenario, seed,
split, variant
("dev" | "held_out" | null for runs without an attack), status, attack {type, params},
events (labels, scenario time t), flight_s (takeoff to touchdown), physics {observable_s,
armed_s} (when the physics engine's heading became observable and its longest horizon armed),
distance_track [[t, d_m], ...] (about 1 Hz, see distance_track) and episodes
[{agent, class, severity, t_start, t_end, evidence_types}] from replaying the run through both agents, and
baseline_episodes in the same format: what stock ArduPilot itself flagged (see baseline.py).
An episode carries "artefact": "old_sizing" (a genuine command whose signature copies were all
lost under the old 2-copy sizing) only when ``old_sizing`` proves it: see there. The command
exports only runs with status "ok" and lists the others with their status.
--guard exports only the runs the calibration guard accepts (calibration.select). A run recorded
as a test seed is exported only into the test split.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from .baseline import baseline_episodes
from .evaluate import CPCE_CALIB, ESTIMATOR_CALIB, LINK_CURVES, evaluate

ROOT = Path(__file__).resolve().parent.parent
SPLITS = ("calibration", "validation", "test")
# Commit b747b3e (2026-09-27 04:09:14 +0530) sized the command-signature copies from the measured
# uplink loss; flights recorded before it sent 2 copies, so a lossy uplink could leave a genuine
# command without a verifiable signature ("unsigned_command").
SIGNATURE_SIZING_FIX_T = 1790462354


def _code_version() -> str:
    """The commit of the evaluating code ("<sha>+dirty" with uncommitted changes)."""
    from .scenario import code_version

    return code_version()


def flown_at(labels: dict) -> str:
    """The code version a run was flown with: its recorded code_version; otherwise
    "before-b747b3e" if it was recorded before that commit, else "unknown"."""
    if labels.get("code_version"):
        return str(labels["code_version"])
    t0 = labels.get("t0_wall")
    return "before-b747b3e" if t0 is not None and t0 < SIGNATURE_SIZING_FIX_T else "unknown"


SIGNATURE_EVIDENCE = {"unsigned_command", "unsafe_command"}
MATCH_S = 2.0  # onboard/ground reception of the same frame; also how far before an episode to look


def lost_signature_evidence(ep: dict) -> bool:
    """Formed by a missing command signature (and, for a safety-relevant command, its consequence)."""
    types = set(ep.get("evidence_types") or [])
    return "unsigned_command" in types and types <= SIGNATURE_EVIDENCE


def uplink_commands(run: Path, t0: float) -> tuple[list, list]:
    """Command frames (scenario time, exact bytes) as the onboard agent received them from the radio
    (onboard_U.tlog) and as the GCS sent them, before the radio (ground_U.tlog)."""
    from pymavlink import mavutil

    from .cmd_sign import is_command

    def read(name):
        path = run / name
        if not path.exists():
            return []
        log = mavutil.mavlink_connection(str(path), robust_parsing=True)
        out = []
        while (m := log.recv_msg()) is not None:
            if m.get_type() != "BAD_DATA" and is_command(m):
                out.append((m._timestamp - t0, bytes(m.get_msgbuf())))
        return out

    return read("onboard_U.tlog"), read("ground_U.tlog")


def old_sizing(ep: dict, onboard: list, ground: list) -> tuple[list, str]:
    """Is this episode a genuine command whose signature was lost (old 2-copy sizing)? Every command
    frame the onboard agent received from t_start - MATCH_S to t_end must be byte-identical to a
    frame the GCS sent within MATCH_S, and received no more often than the GCS sent it (a replay
    would be an extra copy). An injected frame has no ground copy. Returns (matched_uplink entries,
    reason); entries are empty unless every condition holds."""
    t1 = ep["t_end"] if ep.get("t_end") is not None else ep["t_start"]
    frames = [(t, b) for t, b in onboard if ep["t_start"] - MATCH_S <= t <= t1]
    if not frames:
        return [], "no command frame received in the interval"
    matched = []
    for t, b in frames:
        near = [tg for tg, bg in ground if bg == b and abs(tg - t) <= MATCH_S]
        if not near:
            return [], "a received command frame the GCS never sent"
        received = sum(1 for _, x in frames if x == b)
        sent = len({tg for tg, bg in ground if bg == b and any(abs(tg - to) <= MATCH_S for to, x in frames if x == b)})
        if received > sent:
            return [], "a command frame received more often than the GCS sent it"
        tg = min(near, key=lambda x: abs(x - t))
        matched.append(
            {"frame_sha256_8": hashlib.sha256(b).hexdigest()[:8], "onboard_t": round(t, 2), "ground_t": round(tg, 2)}
        )
    return matched, "matched"


def old_sizing_marks(run: Path, episodes: list[dict], flown_at: str) -> dict[int, list[dict]]:
    """The old-sizing rule, in one place for every scorer: {episode index: matched_uplink} for the
    episodes of a recorded run that are a genuine command whose signature copies were all lost —
    the run was flown before the sizing fix ("before-b747b3e"), the episode is formed by
    unsigned_command (with at most unsafe_command beside it), and ``old_sizing`` matches every
    command frame received around it to one the ground station sent."""
    if flown_at != "before-b747b3e":
        return {}
    cand = [i for i, ep in enumerate(episodes) if lost_signature_evidence(ep)]
    if not cand:
        return {}
    uplink = uplink_commands(run, json.loads((run / "labels.json").read_text())["t0_wall"])
    out = {}
    for i in cand:
        matched, _ = old_sizing(episodes[i], *uplink)
        if matched:
            out[i] = matched
    return out


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


def calibration_used() -> dict:
    """{file name: git blob hash} of the calibration files the IDS loads (present ones only)."""
    out = {}
    for f in (CPCE_CALIB, LINK_CURVES, ESTIMATOR_CALIB):
        if f.exists():
            data = f.read_bytes()
            out[f.name] = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
    return out


def distance_track(run: Path, t0: float, every_s: float = 1.0) -> list[list[float]]:
    """[[t, d_m], ...] about once per ``every_s``: horizontal distance from home of the position the
    ground agent received (GLOBAL_POSITION_INT, the autopilot's estimate, so a GNSS spoof moves it
    too), home = first fix after takeoff; scenario time."""
    from pymavlink import mavutil

    log = mavutil.mavlink_connection(str(run / "ground_D.tlog"), robust_parsing=True)
    out: list[list[float]] = []
    home = None
    while (m := log.recv_match(type="GLOBAL_POSITION_INT")) is not None:
        t = m._timestamp - t0
        if t < 0 or m.get_srcSystem() != 1 or not (m.lat or m.lon):
            continue
        lat, lon = m.lat / 1e7, m.lon / 1e7
        home = home or (lat, lon)
        if out and t - out[-1][0] < every_s:
            continue
        dn = math.radians(lat - home[0]) * 6371000.0
        de = math.radians(lon - home[1]) * 6371000.0 * math.cos(math.radians(home[0]))
        out.append([round(t, 2), round(math.hypot(dn, de), 1)])
    return out


def check_output(out: Path, evaluated_with: str, allow_dirty: bool = False) -> None:
    """Exports under results/ must come from committed code: refuse a dirty evaluating tree there.
    ``allow_dirty`` is accepted only for scratch output outside results/."""
    if not evaluated_with.endswith("+dirty"):
        return
    inside = out.resolve().is_relative_to((ROOT / "results").resolve())
    if inside or not allow_dirty:
        raise SystemExit(
            f"the evaluating code has uncommitted changes ({evaluated_with}); commit it before exporting"
            + (" under results/" if inside else ", or pass --allow-dirty for a scratch output outside results/")
        )


def export_run(
    run: Path,
    split: str,
    out_root: Path = ROOT / "results" / "runs",
    source: str | None = None,
    evaluated_with: str | None = None,
) -> Path:
    if split not in SPLITS:
        raise ValueError(f"split must be one of {SPLITS}")
    labels = json.loads((run / "labels.json").read_text())
    if labels.get("split") == "test" and split != "test":
        raise ValueError(f"{run}: a test seed; it may only be exported into the test split")
    source = source or labels["run_id"]
    events = [{k: v for k, v in e.items() if k != "wall"} for e in labels["events"] if e["event"] in KEEP]
    t = {e["event"]: e["t"] for e in events if e["event"] in ("takeoff", "touchdown")}
    attack = labels.get("attack")
    doc = {
        "run_id": labels["run_id"],
        "source": source,
        "flown_at": flown_at(labels),
        "evaluated_with": evaluated_with or _code_version(),
        "calibration": calibration_used(),
        "scenario": labels["scenario"],
        "seed": labels["seed"],
        "split": split,
        "variant": None
        if not attack
        else labels.get("variant") or ("held_out" if labels.get("split") == "heldout" else "dev"),
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
        "physics": {"observable_s": None, "armed_s": None},
        "distance_track": [],
        "episodes": [],
        "baseline_episodes": [],
    }
    if labels["status"] == "ok":
        ev = evaluate(run)
        doc["physics"] = ev["physics"]
        doc["episodes"] = [
            {k: ep[k] for k in ("agent", "class", "severity", "t_start", "t_end", "evidence_types")}
            for ep in ev["episodes"]
        ]
        for i, matched in old_sizing_marks(run, doc["episodes"], doc["flown_at"]).items():
            doc["episodes"][i]["artefact"] = "old_sizing"
            doc["episodes"][i]["matched_uplink"] = matched
        doc["baseline_episodes"] = baseline_episodes(run)
        doc["distance_track"] = distance_track(run, labels["t0_wall"])
    out = out_root / split / f"{source}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=1))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="+", type=Path)
    ap.add_argument("--split", required=True, choices=SPLITS)
    ap.add_argument("--out", type=Path, default=ROOT / "results" / "runs")
    ap.add_argument("--raw-root", type=Path, help="name each export by the run's path under this directory")
    ap.add_argument("--guard", action="store_true", help="only runs the calibration guard accepts")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--allow-dirty", action="store_true", help="scratch output outside results/ from uncommitted code")
    a = ap.parse_args()
    version = _code_version()
    check_output(a.out, version, a.allow_dirty)
    runs = []
    for r in a.runs:  # only flights that ran as planned; any other status is listed, not exported
        status = json.loads((r / "labels.json").read_text())["status"] if (r / "labels.json").exists() else None
        if status == "ok":
            runs.append(r)
        else:
            print(f"{a.split} skip {r}: status {status}")
    if a.guard:
        from .calibration import select

        runs = select(runs, workers=a.workers)
    sources = [str(r.resolve().relative_to(a.raw_root.resolve())) if a.raw_root else None for r in runs]
    if len({s or r.name for s, r in zip(sources, runs, strict=True)}) != len(runs):
        raise SystemExit("two runs would be written to the same file; pass --raw-root")
    with ProcessPoolExecutor(a.workers) as ex:
        n = len(runs)
        for out in ex.map(export_run, runs, [a.split] * n, [a.out] * n, sources, [version] * n):
            print(out)


if __name__ == "__main__":
    main()
