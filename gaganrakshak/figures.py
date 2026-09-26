"""Report figures from the benchmark outputs only (per-run exports, bench summary, stress JSONs);
nothing here replays a recording.

    python -m gaganrakshak.figures results/runs/test --stress results/stress --out results/figures
    python -m gaganrakshak.figures results/bench/summary.json --out results/figures

From an export directory every figure is drawn; from a summary.json the ones that need per-run
data (latency distribution, confusion matrix) are skipped. Each figure is written as PNG (200 dpi)
and SVG, readable in greyscale (hatches and markers carry the distinction, not colour alone).

1 latency.*      detection latency during the attack, per attack type (box + points)
2 drift_rate.*   GNSS drift: detection rate and latency vs drift rate, coherent vs naive
                 (+ the accelerating early-start curve)
3 false_alarms.* false alarms per clean flight-hour by distance band, 95 % upper bounds; ground phase
4 confusion.*    attack type -> alarm classes raised in the attack window (runs)
5 vs_ardupilot.* GaganRakshak vs stock-ArduPilot indicators per attack scenario
6 compute.*      CPU, memory and physics cost per agent (stress measurements)
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

import numpy as np

from . import bench

NOTE = "SITL, simulated"
GREYS = ("0.15", "0.55", "0.85", "0.35", "0.7")
HATCHES = ("", "//", "xx", "..", "\\\\")
MARKERS = ("o", "s", "^", "D", "v")
RATE = re.compile(r"^(a2n?)_gps_drift(?:_naive)?-r([\d.]+)$")
ACCEL = re.compile(r"^a2a_gps_drift_accel-a([\d.]+)-early$")


def _plt():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "font.size": 9,
            "axes.grid": True,
            "axes.axisbelow": True,
            "grid.color": "0.9",
            "savefig.bbox": "tight",
            "figure.constrained_layout.use": True,
        }
    )
    return plt


def _save(fig, out: Path, name: str) -> list[Path]:
    paths = [out / f"{name}.png", out / f"{name}.svg"]
    fig.savefig(paths[0], dpi=200)
    fig.savefig(paths[1])
    fig.clf()
    return paths


def load(source: Path) -> tuple[dict, list[dict] | None]:
    """(metrics as bench.metrics gives them, per-run export docs or None for a summary.json)."""
    if source.is_file():
        return json.loads(source.read_text()), None
    docs = [json.loads(f.read_text()) for f in sorted(source.rglob("*.json"))]
    docs = [d for d in docs if d["status"] == "ok"]
    m = {
        "runs": len(docs),
        "ids": bench.score(docs, "episodes", agent_check=True),
        "baseline": bench.score(docs, "baseline_episodes", agent_check=False),
    }
    return m, docs


def fig_latency(plt, docs: list[dict], out: Path) -> list[Path]:
    lat: dict[str, list[float]] = defaultdict(list)
    runs: dict[str, int] = defaultdict(int)
    for d in docs:
        if d["attack"]:
            t = d["attack"]["type"]
            runs[t] += 1
            r = bench.detection(d, d["episodes"], agent_check=True)
            if r["during"]:
                lat[t].append(r["latency_s"])
    types = sorted(runs)
    fig, ax = plt.subplots(figsize=(7, 3.6))
    lat = defaultdict(list, {t: [max(v, 0.01) for v in xs] for t, xs in lat.items()})  # log axis: floor 10 ms
    data = [lat[t] or [np.nan] for t in types]
    ax.boxplot(data, widths=0.5, showfliers=False, medianprops={"color": "black"})
    for i, t in enumerate(types, start=1):
        ax.plot(
            np.full(len(lat[t]), i) + np.linspace(-0.12, 0.12, len(lat[t])), lat[t], "o", ms=3, mfc="none", mec="0.2"
        )
    ax.set_xticks(
        range(1, len(types) + 1), [f"{t}\n{len(lat[t])}/{runs[t]} runs" for t in types], rotation=30, ha="right"
    )
    ax.set_ylabel("latency from attack start (s, log scale)")
    ax.set_yscale("log")
    ax.set_title(f"Detection latency during the attack (detected / runs) — {NOTE}")
    return _save(fig, out, "latency")


def fig_drift(plt, m: dict, out: Path) -> list[Path]:
    det = m["ids"]["detection"]
    curves: dict[str, list] = defaultdict(list)
    for g, s in det.items():
        if hit := RATE.match(g):
            curves["coherent (a2)" if hit.group(1) == "a2" else "naive (a2n)"].append((float(hit.group(2)), s))
        elif hit := ACCEL.match(g):
            curves["accelerating, early start (a2a)"].append((float(hit.group(1)), s))
    if not curves:
        return []
    fig, axes = plt.subplots(1, 2 + ("accelerating, early start (a2a)" in curves), figsize=(10, 3.4), squeeze=False)
    ax_rate, ax_lat = axes[0][0], axes[0][1]
    for i, name in enumerate(k for k in sorted(curves) if not k.startswith("accel")):
        pts = sorted(curves[name], key=lambda p: p[0])
        x = [p[0] for p in pts]
        ax_rate.plot(
            x,
            [p[1]["detected_during"] / p[1]["runs"] for p in pts],
            "-" + MARKERS[i],
            color="black",
            label=f"{name}, during",
        )
        ax_rate.plot(
            x,
            [p[1]["at_release"] / p[1]["runs"] for p in pts],
            ":" + MARKERS[i],
            color="0.5",
            mfc="none",
            label=f"{name}, at release",
        )
        lat = [p[1]["latency_during_s"]["median"] if p[1]["latency_during_s"] else np.nan for p in pts]
        ax_lat.plot(x, lat, "-" + MARKERS[i], color="black", label=name)
        for xi, p in zip(x, pts, strict=True):
            ax_rate.annotate(f"n={p[1]['runs']}", (xi, 1.02), fontsize=6, ha="center")
    for ax in (ax_rate, ax_lat):
        ax.set_xscale("log")
        ax.set_xlabel("drift rate (m/s)")
    ax_rate.set_ylabel("fraction of runs detected")
    ax_rate.set_ylim(-0.05, 1.12)
    ax_lat.set_ylabel("median latency during the attack (s)")
    ax_rate.legend(fontsize=6)
    ax_lat.legend(fontsize=6)
    if "accelerating, early start (a2a)" in curves:
        ax = axes[0][2]
        pts = sorted(curves["accelerating, early start (a2a)"], key=lambda p: p[0])
        x = [p[0] for p in pts]
        ax.plot(x, [p[1]["detected_during"] / p[1]["runs"] for p in pts], "-o", color="black", label="during")
        ax.plot(x, [p[1]["at_release"] / p[1]["runs"] for p in pts], ":s", color="0.5", mfc="none", label="at release")
        for xi, p in zip(x, pts, strict=True):
            ax.annotate(f"n={p[1]['runs']}", (xi, 1.02), fontsize=6, ha="center")
        ax.set_xscale("log")
        ax.set_xlabel("spoof acceleration (m/s²)")
        ax.set_ylabel("fraction of runs detected")
        ax.set_ylim(-0.05, 1.12)
        ax.legend(fontsize=6)
    fig.suptitle(f"Coherent and naive GNSS drift: detection vs spoof dynamics — {NOTE}")
    return _save(fig, out, "drift_rate")


def fig_false_alarms(plt, m: dict, out: Path) -> list[Path]:
    fig, (ax, axg) = plt.subplots(1, 2, figsize=(9, 3.4), gridspec_kw={"width_ratios": [4, 1]})
    tools = (("GaganRakshak", m["ids"]["false_alarms"]), ("stock ArduPilot", m["baseline"]["false_alarms"]))
    bands = [b for b in tools[0][1]["by_distance"] if b != "on_ground"]
    x = np.arange(len(bands) + 1)
    w = 0.38
    for i, (name, f) in enumerate(tools):
        rows = [
            f["by_distance"].get(b, {"per_hour": None, "upper95_per_hour": None, "clean_hours": 0, "count": 0})
            for b in bands
        ]
        rows.append(f)  # all airborne clean time
        rate = np.array([r["per_hour"] or 0.0 for r in rows])
        ub = np.array([r["upper95_per_hour"] or 0.0 for r in rows])
        ax.bar(x + (i - 0.5) * w, rate, w, color=GREYS[i], hatch=HATCHES[i], edgecolor="black", label=name)
        ax.errorbar(x + (i - 0.5) * w, rate, yerr=[np.zeros_like(ub), ub - rate], fmt="none", ecolor="black", capsize=3)
        for xi, r, top in zip(x, rows, ub, strict=True):
            ax.annotate(
                f"{r['count']} in\n{r['clean_hours']:.2f} h",
                (xi + (i - 0.5) * w, top),
                fontsize=6,
                ha="center",
                va="bottom",
            )
        g = f["ground_phase_false_alarms"]["count"] if "ground_phase_false_alarms" in f else 0
        axg.bar(i, g, 0.6, color=GREYS[i], hatch=HATCHES[i], edgecolor="black")
    ax.set_xticks(x, [*bands, "all airborne"])
    ax.set_xlabel("distance from home")
    ax.set_ylabel("false alarms per clean flight-hour\n(bar: rate, whisker: 95 % upper bound)")
    ax.legend(fontsize=7)
    axg.set_xticks([0, 1], ["GaganRakshak", "ArduPilot"], rotation=30, ha="right")
    axg.set_ylabel("false alarms (count)")
    axg.set_ylim(0, max(1.0, axg.get_ylim()[1]))
    axg.yaxis.get_major_locator().set_params(integer=True)
    axg.set_title("on the ground", fontsize=8)
    fig.suptitle(f"False alarms (MEDIUM or higher) in clean flight time — {NOTE}")
    return _save(fig, out, "false_alarms")


def fig_confusion(plt, docs: list[dict], out: Path) -> list[Path]:
    counts: dict[tuple[str, str], int] = defaultdict(int)
    runs: dict[str, int] = defaultdict(int)
    for d in docs:
        a = d["attack"]
        if not a:
            continue
        runs[a["type"]] += 1
        cls = {
            e["class"]
            for e in d["episodes"]
            if e["severity"] >= 2 and a["start_s"] <= e["t_start"] <= a["end_s"] + bench.SETTLE_S
        }
        for c in cls or {"(none)"}:
            counts[(a["type"], c)] += 1
    types = sorted(runs)
    classes = sorted({c for _, c in counts} - {"(none)"}) + ["(none)"]
    M = np.array([[counts.get((t, c), 0) for c in classes] for t in types])
    fig, ax = plt.subplots(figsize=(1.2 + 0.8 * len(classes), 1.0 + 0.45 * len(types)))
    ax.imshow(M, cmap="Greys", vmin=0, vmax=max(1, M.max()) * 1.6)
    ax.grid(False)
    for i, t in enumerate(types):
        exp = bench.EXPECTED[t][0]
        for j, c in enumerate(classes):
            ax.text(
                j, i, str(M[i, j]), ha="center", va="center", fontsize=8, fontweight="bold" if c == exp else "normal"
            )
    ax.set_xticks(range(len(classes)), classes, rotation=35, ha="right")
    ax.set_yticks(range(len(types)), [f"{t} (n={runs[t]})" for t in types])
    ax.set_xlabel(f"alarm class raised from attack start to attack end + {bench.SETTLE_S:g} s (runs; bold = expected)")
    ax.set_ylabel("attack type")
    ax.set_title(f"Attack type vs alarm classes, GaganRakshak — {NOTE}")
    return _save(fig, out, "confusion")


def fig_vs_ardupilot(plt, m: dict, out: Path) -> list[Path]:
    groups = [g for g in m["ids"]["detection"] if not (RATE.match(g) or ACCEL.match(g))]
    if not groups:
        return []
    fig, (ax_r, ax_l) = plt.subplots(2, 1, figsize=(8, 5.6), sharex=True)
    x = np.arange(len(groups))
    w = 0.38
    for i, key in enumerate(("ids", "baseline")):
        det = m[key]["detection"]
        rate = [det[g]["detected_during"] / det[g]["runs"] for g in groups]
        lat = [max(det[g]["latency_during_s"]["median"], 0.01) if det[g]["latency_during_s"] else 0.0 for g in groups]
        label = "GaganRakshak" if key == "ids" else "stock ArduPilot indicators"
        ax_r.bar(x + (i - 0.5) * w, rate, w, color=GREYS[i], hatch=HATCHES[i], edgecolor="black", label=label)
        ax_l.bar(x + (i - 0.5) * w, lat, w, color=GREYS[i], hatch=HATCHES[i], edgecolor="black", label=label)
        for xi, g in zip(x, groups, strict=True):
            if not det[g]["latency_during_s"]:
                ax_l.annotate("none", (xi + (i - 0.5) * w, 0.02), fontsize=6, rotation=90, ha="center", va="bottom")
    n = m["ids"]["detection"]
    ax_l.set_xticks(x, [f"{g}\n(n={n[g]['runs']})" for g in groups], rotation=35, ha="right", fontsize=7)
    ax_r.set_ylabel("fraction detected during the attack")
    ax_r.set_ylim(0, 1.05)
    ax_l.set_ylabel("median latency during the attack (s, log scale)")
    ax_l.set_yscale("log")
    ax_r.legend(fontsize=7)
    fig.suptitle(f"GaganRakshak vs stock-ArduPilot indicators, per attack scenario — {NOTE}")
    return _save(fig, out, "vs_ardupilot")


def fig_compute(plt, stress_dir: Path, out: Path) -> list[Path]:
    docs = [json.loads(f.read_text()) for f in sorted(stress_dir.glob("*.json"))]
    if not docs:
        return []
    labels = [f"{d['run_id']}\n{d['mode']}, load {d.get('load_avg_1m_at_start', '?')}" for d in docs]  # load: 1 min avg
    platform = sorted({d.get("platform", "?") for d in docs})
    fig, axes = plt.subplots(2, 2, figsize=(12, 7.5))
    x = np.arange(len(docs))
    w = 0.38
    for i, side in enumerate(("onboard", "ground")):
        a = [d["agents"][side] for d in docs]
        kw = {"color": GREYS[i], "hatch": HATCHES[i], "edgecolor": "black", "label": side}
        axes[0][0].bar(x + (i - 0.5) * w, [s["cpu_pct_one_core"] for s in a], w, **kw)
        rss = [s["peak_rss_mb"] - s.get("timing_buffers_mb", 0.0) for s in a]
        axes[0][1].bar(x + (i - 0.5) * w, rss, w, **kw)
    for j, (key, title) in enumerate(
        (("per_gnss_fix", "per new GNSS fix (all horizons)"), ("per_imu_sample", "per IMU sample"))
    ):
        ax = axes[1][j]
        ph = [d["agents"]["onboard"].get("physics", {}).get(key, {}) for d in docs]
        for k, q in enumerate(("p50_ms", "p99_ms")):
            ax.bar(
                x + (k - 0.5) * w,
                [p.get(q, 0.0) for p in ph],
                w,
                color=GREYS[k + 2],
                hatch=HATCHES[k + 2],
                edgecolor="black",
                label=q[:3],
            )
        ax.set_ylabel(f"physics cost {title} (ms)")
        ax.legend(fontsize=7)
    axes[0][0].set_ylabel("CPU (% of one core)")
    axes[0][1].set_ylabel("peak resident memory (MB)\n(measurement buffers excluded)")
    for ax in axes.flat:
        ax.set_xticks(x, labels, fontsize=6, rotation=20, ha="right")
    axes[0][0].legend(fontsize=7)
    fig.suptitle(f"IDS resource use, {', '.join(platform)} — {NOTE}")
    return _save(fig, out, "compute")


def draw(source: Path, out: Path, stress: Path | None = None) -> list[Path]:
    plt = _plt()
    out.mkdir(parents=True, exist_ok=True)
    m, docs = load(source)
    paths: list[Path] = []
    if docs is not None:
        paths += fig_latency(plt, docs, out)
        paths += fig_confusion(plt, docs, out)
    paths += fig_drift(plt, m, out)
    paths += fig_false_alarms(plt, m, out)
    paths += fig_vs_ardupilot(plt, m, out)
    if stress is not None:
        paths += fig_compute(plt, stress, out)
    plt.close("all")
    return paths


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source", type=Path, help="export directory (e.g. results/runs/test) or bench summary.json")
    ap.add_argument("--stress", type=Path, default=None, help="directory of stress JSONs")
    ap.add_argument("--out", type=Path, default=bench.ROOT / "results" / "figures")
    a = ap.parse_args()
    for p in draw(a.source, a.out, a.stress):
        print(p)


if __name__ == "__main__":
    main()
