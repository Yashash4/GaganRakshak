import json
from pathlib import Path

import pytest

from gaganrakshak.calibration import usable

RAW = Path(__file__).parent.parent / "results" / "raw"


def run_dir(tmp_path, name="r", status="ok", attack=None, events=("takeoff", "touchdown", "end")):
    d = tmp_path / name
    d.mkdir()
    (d / "labels.json").write_text(json.dumps({"status": status, "attack": attack,
                                               "events": [{"event": e, "t": 0} for e in events]}))
    return d


def test_rejects_failed_attacked_or_anomalous_runs(tmp_path):
    assert usable(run_dir(tmp_path, "a"), check_ids=False)[0]
    assert not usable(run_dir(tmp_path, "b", status="failed: x"), check_ids=False)[0]
    assert not usable(run_dir(tmp_path, "c", attack={"type": "jamming"}), check_ids=False)[0]
    assert not usable(run_dir(tmp_path, "d", events=("takeoff", "touchdown_not_seen", "end")), check_ids=False)[0]


@pytest.mark.skipif(not (RAW / "calib" / "b5_link_fade-s103").exists(), reason="recorded run not present")
def test_rejects_run_with_ids_episode():
    """b5-s103 was flown with the old harness, which force-disarmed in flight: the IDS flags it."""
    ok, why = usable(RAW / "calib" / "b5_link_fade-s103")
    assert not ok and "IDS episodes" in why
