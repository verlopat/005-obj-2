"""Unit tests for the blockchain-logger service components."""
import json
import pytest
from unittest.mock import MagicMock, patch

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "services", "blockchain-logger"))

from crypto_utils import canonical_json, hash_event, sha256_digest
from schemas import SecurityEventMessage
from retry import exponential_backoff


class TestCryptoUtils:
    def test_sha256_deterministic(self):
        data = b"hello world"
        assert sha256_digest(data) == sha256_digest(data)

    def test_canonical_json_is_sorted(self):
        payload = {"z": 1, "a": 2, "m": 3}
        result = canonical_json(payload)
        assert result == b'{"a":2,"m":3,"z":1}'

    def test_hash_event_deterministic(self):
        event = {"event_id": "abc", "severity": "HIGH", "asset_id": "x"}
        assert hash_event(event) == hash_event(event)

    def test_hash_event_changes_with_content(self):
        e1 = {"event_id": "abc", "severity": "HIGH"}
        e2 = {"event_id": "abc", "severity": "LOW"}
        assert hash_event(e1) != hash_event(e2)


class TestSecurityEventMessage:
    def test_valid_event(self):
        event = SecurityEventMessage(
            event_id="evt-001",
            asset_id="cloud-asset-1",
            cloud_provider="AWS",
            region="us-east-1",
            severity="HIGH",
            description="Test event",
            timestamp="2024-01-01T00:00:00Z",
        )
        assert event.event_id == "evt-001"
        assert event.attack_category == "UNKNOWN"
        assert event.detection_confidence == 1.0

    def test_defaults_applied(self):
        event = SecurityEventMessage(
            event_id="evt-002",
            asset_id="a",
            cloud_provider="GCP",
            region="eu",
            severity="LOW",
            description="desc",
            timestamp="2024-01-01T00:00:00Z",
        )
        assert event.model_version == "v1.0"


class TestExponentialBackoff:
    def test_succeeds_first_attempt(self):
        @exponential_backoff(max_retries=3, base_delay=0.001)
        def success():
            return "ok"
        assert success() == "ok"

    def test_retries_on_failure(self):
        call_count = [0]

        @exponential_backoff(max_retries=3, base_delay=0.001)
        def flaky():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("transient")
            return "recovered"

        result = flaky()
        assert result == "recovered"
        assert call_count[0] == 3

    def test_raises_after_max_retries(self):
        @exponential_backoff(max_retries=2, base_delay=0.001)
        def always_fails():
            raise RuntimeError("permanent")

        with pytest.raises(RuntimeError, match="permanent"):
            always_fails()
