"""Tests for on-chain / IPFS integrity verification."""
import hashlib
import json
import pytest
from unittest.mock import MagicMock, patch

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "services", "blockchain-logger"))

from crypto_utils import canonical_json, sha256_digest, hash_event


class TestIntegrityVerification:
    def test_sha256_matches_ipfs_stored(self):
        payload = {"event_id": "evt-001", "severity": "HIGH", "asset_id": "cloud-1"}
        raw = canonical_json(payload)
        expected = hashlib.sha256(raw).hexdigest()
        assert sha256_digest(raw) == expected

    def test_tampered_payload_detected(self):
        original = {"event_id": "evt-001", "severity": "LOW", "asset_id": "cloud-1"}
        tampered = {"event_id": "evt-001", "severity": "CRITICAL", "asset_id": "cloud-1"}
        assert hash_event(original) != hash_event(tampered)

    def test_canonical_json_order_independent(self):
        a = {"b": 2, "a": 1}
        b = {"a": 1, "b": 2}
        assert canonical_json(a) == canonical_json(b)

    def test_empty_payload_hashes(self):
        h = hash_event({})
        assert len(h) == 64  # SHA-256 hex digest

    def test_unicode_payload_hashes(self):
        payload = {"description": "Détection d'intrusion — 検出"}
        h = hash_event(payload)
        assert len(h) == 64
