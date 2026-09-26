"""Ed25519 signing over canonical JSON.

Background IP: adapted from the team's prior project Reef
(https://github.com/Yashash4/reef-mcp-registry, atlas/app/crypto). Declared in
THIRD_PARTY.md.
"""

from __future__ import annotations

import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_json(payload: Any) -> bytes:
    """Deterministic bytes: sorted keys, compact separators, UTF-8."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_seed_32B, public_key_32B)."""
    sk = Ed25519PrivateKey.generate()
    raw = serialization.Encoding.Raw
    return (
        sk.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()),
        sk.public_key().public_bytes(raw, serialization.PublicFormat.Raw),
    )


def sign(data: bytes, private_seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(private_seed).sign(data)


def verify(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """True on a good signature; False on any mismatch. Never raises."""
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_json(payload: Any, private_seed: bytes) -> bytes:
    return sign(canonical_json(payload), private_seed)


def verify_json(payload: Any, signature: bytes, public_key: bytes) -> bool:
    return verify(canonical_json(payload), signature, public_key)
