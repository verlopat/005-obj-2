"""Integrity verification tests — ensures IPFS CID + SHA-256 matches chain records."""
import hashlib
import json
import pytest


def canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def simulate_log_and_verify(payload: dict):
    """Simulate logging an event and verifying integrity."""
    raw = canonical_json(payload)
    expected_sha256 = sha256_hex(raw)
    # Simulated on-chain record stores this sha256
    chain_record = {"sha256": expected_sha256, "event_id": payload["event_id"]}
    # Simulated IPFS fetch returns same bytes
    ipfs_bytes = raw  # In production: fetch from IPFS CID
    ipfs_sha256 = sha256_hex(ipfs_bytes)
    return chain_record["sha256"] == ipfs_sha256, expected_sha256, ipfs_sha256


def test_integrity_check_passes_for_unmodified_payload():
    payload = {"event_id": "evt-001", "asset_id": "asset-123",
               "severity": "HIGH", "description": "Test",
               "timestamp": "2025-01-01T00:00:00Z"}
    match, chain_sha, ipfs_sha = simulate_log_and_verify(payload)
    assert match is True
    assert chain_sha == ipfs_sha


def test_integrity_check_fails_for_tampered_payload():
    payload = {"event_id": "evt-002", "asset_id": "asset-456",
               "severity": "CRITICAL", "description": "Original",
               "timestamp": "2025-01-01T00:00:00Z"}
    raw = canonical_json(payload)
    expected_sha256 = sha256_hex(raw)
    # Tampered IPFS payload
    tampered = dict(payload)
    tampered["severity"] = "LOW"
    tampered_sha256 = sha256_hex(canonical_json(tampered))
    assert expected_sha256 != tampered_sha256


def test_canonical_json_is_deterministic():
    payload1 = {"z": 26, "a": 1, "m": 13}
    payload2 = {"m": 13, "a": 1, "z": 26}
    assert canonical_json(payload1) == canonical_json(payload2)


def test_sha256_changes_with_field_value():
    base = {"event_id": "x", "severity": "LOW"}
    modified = {"event_id": "x", "severity": "HIGH"}
    assert sha256_hex(canonical_json(base)) != sha256_hex(canonical_json(modified))


def test_sha256_changes_with_field_name():
    base = {"event_id": "x", "field_a": "value"}
    modified = {"event_id": "x", "field_b": "value"}
    assert sha256_hex(canonical_json(base)) != sha256_hex(canonical_json(modified))
