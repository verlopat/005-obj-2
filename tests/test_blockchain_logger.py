"""Unit tests for the blockchain-logger service."""
import json
import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime

# Test crypto utilities
from unittest.mock import patch as mock_patch
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'services', 'blockchain-logger'))

from crypto_utils import sha256_digest, canonical_json, hash_event

def test_sha256_digest_deterministic():
    data = b"test payload"
    assert sha256_digest(data) == sha256_digest(data)
    assert len(sha256_digest(data)) == 64

def test_canonical_json_sorted_keys():
    payload1 = {"b": 2, "a": 1}
    payload2 = {"a": 1, "b": 2}
    assert canonical_json(payload1) == canonical_json(payload2)

def test_canonical_json_nested():
    payload = {"event_id": "123", "severity": "HIGH", "nested": {"z": 1, "a": 2}}
    raw = canonical_json(payload)
    parsed = json.loads(raw)
    assert parsed["event_id"] == "123"

def test_hash_event_deterministic():
    payload = {"event_id": "abc", "severity": "LOW", "asset_id": "x"}
    h1 = hash_event(payload)
    h2 = hash_event(payload)
    assert h1 == h2

def test_hash_event_sensitivity():
    payload1 = {"event_id": "abc", "severity": "LOW"}
    payload2 = {"event_id": "abc", "severity": "HIGH"}
    assert hash_event(payload1) != hash_event(payload2)

# Test retry decorator
from retry import exponential_backoff

def test_retry_success_on_first_attempt():
    counter = {"calls": 0}
    @exponential_backoff(max_retries=3)
    def succeed():
        counter["calls"] += 1
        return "ok"
    assert succeed() == "ok"
    assert counter["calls"] == 1

def test_retry_succeeds_after_failures():
    counter = {"calls": 0}
    @exponential_backoff(max_retries=3, base_delay=0.01)
    def flaky():
        counter["calls"] += 1
        if counter["calls"] < 3:
            raise ConnectionError("Transient failure")
        return "ok"
    assert flaky() == "ok"
    assert counter["calls"] == 3

def test_retry_exhausted_raises():
    @exponential_backoff(max_retries=2, base_delay=0.01)
    def always_fails():
        raise RuntimeError("Permanent failure")
    with pytest.raises(RuntimeError, match="Permanent failure"):
        always_fails()

def test_retry_specific_exception_only():
    @exponential_backoff(max_retries=3, base_delay=0.01, exceptions=(ConnectionError,))
    def raises_value_error():
        raise ValueError("Not retried")
    with pytest.raises(ValueError):
        raises_value_error()
