"""Legitimate commands whose signature never arrived, per distance band.

For each recorded flight: every command the ground station sent (ground_U.tlog) is one trial,
placed in the distance band of the position the ground agent last received when it was sent. A
trial fails when the onboard verifier judged that same frame (matched by its exact bytes)
``unsigned`` -- no valid signature copy arrived within the wait. Attack windows are not excluded:
the question is how often the signature channel itself fails.

    python tools/signature_loss.py --out results/bench/signature_loss results/raw/test/b5_link_fade-s* \\
        results/raw/test/*_far-s*
"""

from __future__ import annotations

import argparse
import bisect
import json
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

BANDS = ((0, 100), (100, 200), (200, 300), (300, 400), (400, None))


def band_of(d: float) -> str:
    for lo, hi in BANDS:
        if hi is None or d < hi:
            return f"{lo}-{hi} m" if hi is not None else f">{lo} m"
    raise AssertionError


def one(run: Path) -> dict:
    from pymavlink import mavutil

    import gaganrakshak.cmd_sign as cs
    import gaganrakshak.mavlink  # noqa: F401  (registers the GR messages)
    from gaganrakshak.evaluate import evaluate
    from gaganrakshak.export import distance_track

    unsigned: Counter[bytes] = Counter()
    orig = cs.CmdVerifier.tick

    def tick(self, t):  # frames judged unsigned now: waited past wait_s with no signature for their key
        for k, frames in self._cmds.items():
            if not self._sigs.get(k):
                unsigned.update(f for t_cmd, f, _ in frames if t - t_cmd > self.wait_s)
        return orig(self, t)

    cs.CmdVerifier.tick = tick
    try:
        evaluate(run)
    finally:
        cs.CmdVerifier.tick = orig
    t0 = json.loads((run / "labels.json").read_text())["t0_wall"]
    track = distance_track(run, t0)
    ts = [x[0] for x in track]
    trials: Counter[str] = Counter()
    fails: Counter[str] = Counter()
    log = mavutil.mavlink_connection(str(run / "ground_U.tlog"), robust_parsing=True)
    while (m := log.recv_msg()) is not None:
        if m.get_type() == "BAD_DATA" or not cs.is_command(m):
            continue
        i = bisect.bisect_right(ts, m._timestamp - t0) - 1
        b = band_of(track[i][1] if i >= 0 else 0.0)
        trials[b] += 1
        frame = bytes(m.get_msgbuf())
        if unsigned[frame] > 0:
            unsigned[frame] -= 1
            fails[b] += 1
    return {"run": run.name, "trials": dict(trials), "unsigned": dict(fails)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="+", type=Path)
    ap.add_argument("--out", type=Path, required=True, help="writes <out>.json and <out>.md")
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    with ProcessPoolExecutor(a.workers) as ex:
        per_run = list(ex.map(one, sorted(a.runs)))
    tot_n: Counter[str] = Counter()
    tot_k: Counter[str] = Counter()
    for r in per_run:
        tot_n.update(r["trials"])
        tot_k.update(r["unsigned"])
    order = [band_of(lo) for lo, _ in BANDS]
    rows = [{"band": b, "commands": tot_n[b], "unsigned": tot_k[b]} for b in order if tot_n[b]]
    total = {"commands": sum(tot_n.values()), "unsigned": sum(tot_k.values())}
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.with_suffix(".json").write_text(json.dumps({"total": total, "by_band": rows, "runs": per_run}, indent=1))
    md = ["| band | commands sent | unsigned onboard | rate |", "|---|---|---|---|"]
    for r in [*rows, {"band": "all", **total}]:
        md.append(f"| {r['band']} | {r['commands']} | {r['unsigned']} | {r['unsigned'] / r['commands']:.3%} |")
    a.out.with_suffix(".md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
