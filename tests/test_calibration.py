import json
from pathlib import Path

import pytest

from gaganrakshak.calibration import usable

RAW = Path(__file__).parent.parent / "results" / "raw"


def run_dir(tmp_path, name="r", status="ok", attack=None, events=("takeoff", "touchdown", "end")):
    d = tmp_path / name
    d.mkdir()
    (d / "labels.json").write_text(
        json.dumps({"status": status, "attack": attack, "events": [{"event": e, "t": 0} for e in events]})
    )
    return d


def test_rejects_failed_attacked_or_anomalous_runs(tmp_path):
    assert usable(run_dir(tmp_path, "a"), check_ids=False)[0]
    assert not usable(run_dir(tmp_path, "b", status="failed: x"), check_ids=False)[0]
    assert not usable(run_dir(tmp_path, "c", attack={"type": "jamming"}), check_ids=False)[0]
    assert not usable(run_dir(tmp_path, "d", events=("takeoff", "touchdown_not_seen", "end")), check_ids=False)[0]


A3_RUN = RAW / "att" / "a3_cmd_injection-s1"


@pytest.mark.skipif(not A3_RUN.exists(), reason="recorded injection run not present")
def test_rejects_run_with_unauthorised_evidence(tmp_path):
    """An injected command is rejected by the IDS evidence alone, even with the attack label removed."""
    import shutil

    run = tmp_path / "unlabelled"
    shutil.copytree(A3_RUN, run, ignore=shutil.ignore_patterns("sitl"))
    labels = json.loads((run / "labels.json").read_text())
    labels["attack"] = None
    (run / "labels.json").write_text(json.dumps(labels))
    ok, why = usable(run)
    # a lost signature alone is not disqualifying (clean fades lose them), but what the injection did is
    assert not ok and "uncommanded_mode_change" in why
