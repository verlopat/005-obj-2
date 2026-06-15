"""Cryptographic utilities: SHA-256 hashing, canonical JSON serialization."""
import hashlib
import json
from typing import Any, Dict


def canonical_json(payload: Dict[str, Any]) -> bytes:
    """Deterministic JSON bytes — sorted keys, no extra whitespace."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sha256_digest(data: bytes) -> str:
    """Return lowercase hex SHA-256 of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_event(payload: Dict[str, Any]) -> str:
    """Return SHA-256 of the canonical JSON representation of payload."""
    return sha256_digest(canonical_json(payload))
