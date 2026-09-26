import shutil
from pathlib import Path

from gaganrakshak import crypto
from gaganrakshak.evidence import EvidenceEvent, Severity
from gaganrakshak.evidence_log import EvidenceLog, verify_log
from gaganrakshak.ids import Ids, run_replay
from gaganrakshak.sample import Status

FIXTURE = Path(__file__).parent / "data" / "sitl_flight.tlog"


class LandFlagger:
    """Toy detector: HIGH evidence on every Status sample while in LAND."""

    def __init__(self):
        self.seen_directions = set()
        self.ticks = 0

    def observe(self, msg, samples, direction, t):
        self.seen_directions.add(direction)
        return [EvidenceEvent(t, 1, "toy", "in_land", 1.0, Severity.HIGH, "toy_class")
                for s in samples if isinstance(s.payload, Status) and s.payload.mode == "LAND"]

    def tick(self, t):
        self.ticks += 1
        return []


def test_replay_runs_detectors_to_one_logged_episode(tmp_path):
    shutil.copy(FIXTURE, tmp_path / "onboard_D.tlog")  # recorded-run layout: <side>_<dir>.tlog
    det = LandFlagger()
    ids = run_replay(Ids([det], log=EvidenceLog(tmp_path / "evidence.jsonl")), tmp_path / "onboard")

    assert len(ids.alerts) > 10  # LAND lasted ~20 s of 1-50 Hz status
    assert len(ids.tracker.episodes) == 1  # ...but it is one alarm
    assert ids.tracker.episodes[0].attack_class == "toy_class"
    assert det.seen_directions == {"D"} and det.ticks > 500  # ~100 s at 10 Hz
    assert not ids.adapter.stats["unknown"]

    sk, pk = crypto.generate_keypair()
    entries = EvidenceLog(tmp_path / "evidence.jsonl").entries  # reload from disk
    assert [e["record"]["kind"] for e in entries] == ["episode_opened"]
    assert verify_log(entries, ids.log.signed_root(sk), pk)
