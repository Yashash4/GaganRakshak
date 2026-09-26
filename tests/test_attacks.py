"""Every link attack, flown once in SITL, raises its class inside the attack window and
nothing of that class before it starts."""

from pathlib import Path

import pytest
import yaml

from gaganrakshak import sitl
from gaganrakshak.evaluate import evaluate
from gaganrakshak.scenario import resolve, run_many

SCEN = Path(__file__).parent.parent / "scenarios"
EXPECTED = {  # scenario -> (agent, class)
    "a3_cmd_injection": ("onboard", "command_injection"),
    "a4_telemetry_position": ("ground", "telemetry_manipulation"),
    "a5_link_flood": ("ground", "dos"),
    "a6_param_tamper": ("onboard", "integrity_violation"),
    "a7_replay": ("onboard", "replay"),
    "a8_fc_impersonation": ("ground", "telemetry_manipulation"),
    "a9_jamming": ("ground", "dos"),
}


@pytest.mark.sitl
def test_link_attacks_detected_in_window(tmp_path):
    plans = [resolve(yaml.safe_load((SCEN / f"{n}.yaml").read_text()), 11) for n in EXPECTED]
    assert [s for _, s in run_many(plans, tmp_path, workers=len(plans))] == ["ok"] * len(plans)
    for p in plans:
        r = evaluate(tmp_path / p["run_id"])
        agent, cls = EXPECTED[p["scenario"]]
        a = r["attack"]
        started = [e for e in r["attack_events"] if e["event"] == "attack_start"]
        assert started and abs(started[0]["t"] - a["start_s"]) < 0.2, (p["run_id"], r["attack_events"])
        eps = [e for e in r["episodes"] if e["agent"] == agent and e["class"] == cls]
        assert eps and a["start_s"] <= eps[0]["t_start"] <= a["end_s"] + 3, (p["run_id"], r["episodes"])
        assert not [e for e in r["evidence"] if e["class"] == cls and e["t"] < a["start_s"]], p["run_id"]
        assert not any(r["adapter_unknown"].values()), r["adapter_unknown"]
