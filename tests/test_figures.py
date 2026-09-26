import json

import pytest
from test_bench import RUNS, doc, ep, gps  # sibling test module (tests/ is on the path)

pytest.importorskip("matplotlib")

from gaganrakshak import figures  # noqa: E402


def stress_doc():
    agent = {
        "cpu_pct_one_core": 9.0,
        "peak_rss_mb": 180.0,
        "timing_buffers_mb": 20.0,
        "physics": {"per_gnss_fix": {"p50_ms": 3.0, "p99_ms": 7.0}, "per_imu_sample": {"p50_ms": 0.05, "p99_ms": 0.1}},
    }
    return {
        "platform": "DGX Spark",
        "run_id": "b3-s1",
        "mode": "paced",
        "load_avg_1m_at_start": 2.5,
        "agents": {"onboard": agent, "ground": {**agent, "physics": {}}},
    }


def test_every_figure_is_drawn_from_exports_and_stress(tmp_path):
    runs = [*RUNS]
    for rate in (0.5, 2.0):
        runs.append({**doc(f"a2_gps_drift-r{rate}-s5001", gps(), [ep(45.0, "gps_spoofing", 3)]), "split": "test"})
        runs.append({**doc(f"a2n_gps_drift_naive-r{rate}-s5001", gps(), []), "split": "test"})
    runs.append(doc("a2a_gps_drift_accel-a0.01-early-s5001", gps(), [ep(62.0, "gps_spoofing", 3)]))
    exports, stress = tmp_path / "runs", tmp_path / "stress"
    exports.mkdir()
    stress.mkdir()
    for d in runs:
        (exports / f"{d['run_id']}.json").write_text(json.dumps(d))
    (stress / "b3.paced.json").write_text(json.dumps(stress_doc()))
    paths = figures.draw(exports, tmp_path / "out", stress)
    names = {p.name for p in paths}
    for f in ("latency", "drift_rate", "false_alarms", "confusion", "vs_ardupilot", "compute"):
        assert {f"{f}.png", f"{f}.svg"} <= names
    assert all(p.stat().st_size > 1000 for p in paths)


def test_a_summary_json_draws_the_figures_that_need_no_per_run_data(tmp_path):
    from gaganrakshak import bench

    exports = tmp_path / "runs"
    exports.mkdir()
    for d in RUNS:
        (exports / f"{d['run_id']}.json").write_text(json.dumps(d))
    summary = tmp_path / "summary.json"
    summary.write_text(json.dumps(bench.metrics(exports)))
    names = {p.stem for p in figures.draw(summary, tmp_path / "out")}
    assert names == {"false_alarms", "vs_ardupilot"}  # no drift groups; latency/confusion need per-run data
