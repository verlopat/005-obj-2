"""
tests/test_tamper.py

Tamper detection test — unit test that does NOT require a live stack.

Strategy:
  1. Build a valid SecurityEvent and write it to a fake Redis instance.
  2. Mutate the stored SHA-256 (simulates off-chain payload tampering).
  3. Call verify_record() and assert status == HASH_MISMATCH.

Also tests IPFS hash mismatch by patching fetch_and_verify to return False.

Run with:
    LIVE_MODE=0 pytest tests/test_tamper.py -v
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

# Ensure repo root is on path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

os.environ.setdefault("LIVE_MODE", "0")

from shared.event_schema import SecurityEvent, VerificationStatus


def _make_event(**overrides) -> SecurityEvent:
    defaults = dict(
        asset_id="tamper-test-asset",
        cloud_provider="AWS",
        region="us-east-1",
        severity="HIGH",
        attack_category="TAMPER_TEST",
        description="Tamper detection test event",
        detection_confidence=0.95,
        model_version="test-v1",
        timestamp=datetime.now(timezone.utc),
        # Ledger fields
        tx_id="deadbeef" * 8,
        block_number=42,
        ipfs_cid="QmFakeCIDForTamperTest",
        org_msp="Org1MSP",
        agent_identity="CN=agent,O=Org1",
        agent_signature="aabbccdd" * 8,
    )
    defaults.update(overrides)
    e = SecurityEvent(**defaults)
    # Set sha256 to the correct value for the un-tampered event
    e.sha256 = e.compute_sha256()
    return e


def _redis_with_event(event: SecurityEvent) -> MagicMock:
    """Return a mock Redis client that holds one event record."""
    store = {}
    key_prefix = "audit:event:"
    store[key_prefix + str(event.event_id)] = json.dumps(event.to_ledger_dict(), default=str)

    mock_redis = MagicMock()
    mock_redis.get.side_effect = lambda k: store.get(k)
    mock_redis.zrevrange.return_value = []
    return mock_redis


# ─────────────────────────────────────────────────────────────────────────

class TestTamperDetection:

    def test_valid_record_passes(self):
        """A clean record with matching sha256 and passing IPFS verify returns VALID."""
        event = _make_event()
        mock_redis = _redis_with_event(event)

        with (
            patch("services.audit_api.query_service._get_redis", return_value=mock_redis),  # noqa
            patch("shared.ipfs_client.fetch_and_verify", return_value=True),
            patch("services.audit_api.query_service._verify_signature", return_value=True),
        ):
            # Import here so LIVE_MODE=0 is already set
            import importlib
            import services.audit_api.query_service as qs  # type: ignore
            importlib.reload(qs)

            result = qs.verify_record(str(event.event_id))

        assert result.status == VerificationStatus.VALID

    def test_tampered_sha256_detected(self):
        """
        Mutate the stored SHA-256 to a wrong value, then assert that
        verify_record() returns HASH_MISMATCH.
        """
        event = _make_event()
        # Tamper: replace the stored hash with gibberish
        tampered = event.to_ledger_dict()
        tampered["sha256"] = "deadbeef" * 8  # wrong hash

        import json as _json
        store = {"audit:event:" + str(event.event_id): _json.dumps(tampered, default=str)}
        mock_redis = MagicMock()
        mock_redis.get.side_effect = lambda k: store.get(k)

        with (
            patch("shared.ipfs_client.fetch_and_verify", return_value=True),
        ):
            import importlib
            import services.audit_api.query_service as qs  # type: ignore
            importlib.reload(qs)
            qs._redis = mock_redis

            result = qs.verify_record(str(event.event_id))

        assert result.status == VerificationStatus.HASH_MISMATCH, (
            f"Expected HASH_MISMATCH, got {result.status} (detail: {result.detail})"
        )

    def test_ipfs_hash_mismatch_detected(self):
        """
        SHA-256 in Redis is correct but IPFS returns different bytes.
        Expect IPFS_HASH_MISMATCH.
        """
        event = _make_event()
        mock_redis = _redis_with_event(event)

        with (
            patch("shared.ipfs_client.fetch_and_verify", return_value=False),
            patch("services.audit_api.query_service._verify_signature", return_value=True),
        ):
            import importlib
            import services.audit_api.query_service as qs  # type: ignore
            importlib.reload(qs)
            qs._redis = mock_redis

            result = qs.verify_record(str(event.event_id))

        assert result.status == VerificationStatus.IPFS_HASH_MISMATCH, (
            f"Expected IPFS_HASH_MISMATCH, got {result.status}"
        )

    def test_missing_record_returns_cid_not_found(self):
        """Querying a non-existent event_id returns CID_NOT_FOUND."""
        mock_redis = MagicMock()
        mock_redis.get.return_value = None

        with patch("shared.ipfs_client.fetch_and_verify", return_value=True):
            import importlib
            import services.audit_api.query_service as qs  # type: ignore
            importlib.reload(qs)
            qs._redis = mock_redis

            result = qs.verify_record(str(uuid.uuid4()))

        assert result.status == VerificationStatus.CID_NOT_FOUND
