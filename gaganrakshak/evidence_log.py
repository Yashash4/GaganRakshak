"""Tamper-evident evidence log (plan I6).

Append-only JSONL. Each entry carries the hash of the previous entry (hash chain), and
the log can export an Ed25519-signed Merkle root over all entries (RFC 6962 hashing:
leaf = SHA-256(0x00 || data), node = SHA-256(0x01 || left || right)).

Design follows the Reef audit log (Background IP, see THIRD_PARTY.md), reimplemented in
Python.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional

from . import crypto

GENESIS = "0" * 64


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over already-hashed leaves."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def _entry_bytes(entry: dict) -> bytes:
    return crypto.canonical_json(entry)


class EvidenceLog:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else None
        self.entries: list[dict] = []
        self._leaves: list[bytes] = []
        if self.path and self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self._add(json.loads(line), persist=False)

    @property
    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else GENESIS

    def append(self, record: dict[str, Any]) -> dict:
        body = {"index": len(self.entries), "prev": self.head, "record": record}
        entry = {**body, "hash": hashlib.sha256(_entry_bytes(body)).hexdigest()}
        self._add(entry, persist=True)
        return entry

    def _add(self, entry: dict, persist: bool) -> None:
        self.entries.append(entry)
        self._leaves.append(leaf_hash(_entry_bytes(entry)))
        if persist and self.path:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")

    def signed_root(self, private_seed: bytes) -> dict:
        root = merkle_root(self._leaves).hex()
        payload = {"size": len(self.entries), "root": root, "head": self.head}
        return {**payload, "sig": crypto.sign_json(payload, private_seed).hex()}


def verify_log(entries: list[dict], signed_root: dict, public_key: bytes) -> bool:
    """Check hash chain, Merkle root and root signature. False on any tampering."""
    prev = GENESIS
    for i, e in enumerate(entries):
        body = {"index": e.get("index"), "prev": e.get("prev"), "record": e.get("record")}
        if e.get("index") != i or e.get("prev") != prev:
            return False
        if hashlib.sha256(_entry_bytes(body)).hexdigest() != e.get("hash"):
            return False
        prev = e["hash"]
    payload = {k: signed_root[k] for k in ("size", "root", "head")}
    if payload["size"] != len(entries) or payload["head"] != prev:
        return False
    if merkle_root([leaf_hash(_entry_bytes(e)) for e in entries]).hex() != payload["root"]:
        return False
    return crypto.verify_json(payload, bytes.fromhex(signed_root["sig"]), public_key)
