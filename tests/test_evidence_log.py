import copy

from gaganrakshak import crypto
from gaganrakshak.evidence_log import EvidenceLog, verify_log


def _log(n=5):
    log = EvidenceLog()
    for i in range(n):
        log.append({"t": i, "class": "gps_spoofing", "score": i * 0.1})
    return log


def test_clean_log_verifies():
    sk, pk = crypto.generate_keypair()
    log = _log()
    assert verify_log(log.entries, log.signed_root(sk), pk)


def test_tampered_record_fails():
    sk, pk = crypto.generate_keypair()
    log = _log()
    root = log.signed_root(sk)
    entries = copy.deepcopy(log.entries)
    entries[2]["record"]["score"] = 0.0
    assert not verify_log(entries, root, pk)


def test_deleted_or_reordered_entry_fails():
    sk, pk = crypto.generate_keypair()
    log = _log()
    root = log.signed_root(sk)
    assert not verify_log(log.entries[:-1], root, pk)
    swapped = log.entries[:1] + [log.entries[2], log.entries[1]] + log.entries[3:]
    assert not verify_log(swapped, root, pk)


def test_wrong_key_fails():
    sk, _ = crypto.generate_keypair()
    _, other_pk = crypto.generate_keypair()
    log = _log()
    assert not verify_log(log.entries, log.signed_root(sk), other_pk)


def test_log_persists_and_reloads(tmp_path):
    sk, pk = crypto.generate_keypair()
    p = tmp_path / "evidence.jsonl"
    log = EvidenceLog(p)
    for i in range(3):
        log.append({"i": i})
    reloaded = EvidenceLog(p)
    assert reloaded.head == log.head
    assert verify_log(reloaded.entries, log.signed_root(sk), pk)
