"""SHA-256 hashing and deterministic JSON canonicalization."""
import hashlib
import json
from typing import Any, Dict

def sha256_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def canonical_json(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")

def hash_event(payload: Dict[str, Any]) -> str:
    return sha256_digest(canonical_json(payload))
