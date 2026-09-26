import json
from pathlib import Path

import pytest
from pymavlink import mavutil
from pymavlink.dialects.v20 import ardupilotmega as mav

import gaganrakshak  # noqa: F401
from gaganrakshak import crypto
from gaganrakshak.cmd_sign import CmdVerifier, Signer
from gaganrakshak.integrity import IntegrityMonitor, load_baseline, sign_baseline

MAV = mavutil.mavlink
BASE_DIR = Path(__file__).parent.parent / "configs" / "baseline"
SEED, PUB = crypto.generate_keypair()
BASELINE = {"version": {"flight_sw_version": 67568127, "git_hash": "dbe79216"},
            "params": {"FENCE_ENABLE": 0.0, "FS_THR_ENABLE": 1.0}}


class Link:
    """GCS (with a signing ground agent) and FC talking through the onboard IDS."""

    def __init__(self):
        self.gcs = mav.MAVLink(None, srcSystem=255, srcComponent=190)
        self.fc = mav.MAVLink(None, srcSystem=1, srcComponent=1)
        self.signer = Signer(SEED)
        self.verifier = CmdVerifier(PUB)
        self.mon = IntegrityMonitor(BASELINE, self.verifier)
        self.t = 0.0
        self.events = []

    def _feed(self, buf, direction):
        p = mav.MAVLink(None)
        p.robust_parsing = True
        msg = p.parse_char(buf)
        for det in (self.verifier, self.mon):
            self.events += det.observe(msg, [], direction, self.t)
        self.t += 0.01
        return msg

    def up(self, m, signed=True):
        buf = m.pack(self.gcs)
        self.gcs.seq = (self.gcs.seq + 1) % 256
        msg = self._feed(buf, "U")
        if signed:
            for s in self.signer.sign(buf, msg):
                self._feed(s, "U")

    def down(self, m):
        buf = m.pack(self.fc)
        self.fc.seq = (self.fc.seq + 1) % 256
        self._feed(buf, "D")

    def settle(self):
        for _ in range(30):
            self.t += 0.1
            for det in (self.verifier, self.mon):
                self.events += det.tick(self.t)
        return [e.evidence_type for e in self.events]


def pset(name, v):
    return mav.MAVLink_param_set_message(1, 1, name.encode(), v, 9)


def pval(name, v):
    return mav.MAVLink_param_value_message(name.encode(), v, 9, 1370, 1)


def test_signed_param_change_is_legitimate():
    L = Link()
    L.up(pset("FENCE_ENABLE", 1.0))
    L.down(pval("FENCE_ENABLE", 1.0))
    L.down(pval("FS_THR_ENABLE", 1.0))  # unchanged baseline value
    assert L.settle() == []


def test_injected_param_set_is_caught_twice():
    L = Link()
    L.up(pset("FS_THR_ENABLE", 0.0), signed=False)  # attacker disables the RC failsafe
    L.down(pval("FS_THR_ENABLE", 0.0))
    k = L.settle()
    assert "unauthorised_write" in k and "unauthorised_param_change" in k


def test_param_changed_with_no_write_seen():
    L = Link()
    L.down(pval("FENCE_ENABLE", 1.0))
    L.down(pval("FENCE_ENABLE", 1.0))  # repeated report: one alarm
    assert L.settle() == ["unauthorised_param_change"]


def test_unsigned_mission_and_ftp_writes():
    L = Link()
    L.up(mav.MAVLink_mission_count_message(1, 1, 5, 0), signed=False)
    L.up(mav.MAVLink_file_transfer_protocol_message(0, 1, 1, bytes([0, 0, 0, 7]) + bytes(247)), signed=False)
    L.up(mav.MAVLink_mission_count_message(1, 1, 5, 0))  # signed upload: fine
    assert L.settle().count("unauthorised_write") == 2


def test_reported_version_mismatch_is_separate_and_lower():
    L = Link()
    v = lambda h: mav.MAVLink_autopilot_version_message(0, 67568127, 0, 0, 0, h, bytes(8), bytes(8), 0, 0, 0)
    L.down(v(b"dbe79216"))
    L.down(v(b"deadbeef"))
    L.down(v(b"deadbeef"))
    k = L.settle()
    assert k == ["reported_version_mismatch"]
    assert L.events[0].class_hint == "version_mismatch" and L.events[0].severity < 3


def test_real_baseline_verifies_and_tamper_fails(tmp_path):
    pub = bytes.fromhex((BASE_DIR / "ardupilot_copter_sitl.pub").read_text())
    base = load_baseline(BASE_DIR / "ardupilot_copter_sitl.json", pub)
    assert base["params"]["FS_THR_ENABLE"] == 1.0 and len(base["params"]) > 50
    doc = json.loads((BASE_DIR / "ardupilot_copter_sitl.json").read_text())
    doc["baseline"]["params"]["FS_THR_ENABLE"] = 0.0
    (tmp_path / "b.json").write_text(json.dumps(doc))
    with pytest.raises(ValueError):
        load_baseline(tmp_path / "b.json", pub)
    assert sign_baseline(BASELINE, SEED)["signature"]
