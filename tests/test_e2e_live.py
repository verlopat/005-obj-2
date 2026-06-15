"""
tests/test_e2e_live.py

End-to-end integration test — requires a fully running live stack:
  - detector-adapter on :8000
  - blockchain-logger consuming from Kafka, writing to Fabric + IPFS + Redis
  - audit-api on :8001

Run with:
    LIVE_MODE=1 pytest tests/test_e2e_live.py -v

The test:
  1. Posts one security event to the detector-api.
  2. Polls the audit-api until the record appears in Redis (up to 30 s).
  3. Verifies the returned record matches the original event fields.
  4. Calls the /verify/{event_id} endpoint and asserts status == VALID.
  5. Fails the build if any step returns empty or non-VALID.
"""
from __future__ import annotations

import os
import time
import uuid

import pytest
import requests

DETECTOR_URL = os.getenv("DETECTOR_URL", "http://localhost:8000")
AUDIT_URL    = os.getenv("AUDIT_URL",    "http://localhost:8001")

TEST_EVENT = {
    "asset_id":             f"e2e-test-asset-{uuid.uuid4().hex[:8]}",
    "cloud_provider":       "AWS",
    "region":               "us-east-1",
    "severity":             "HIGH",
    "attack_category":      "E2E_TEST",
    "description":          "End-to-end integration test event",
    "detection_confidence": 0.99,
    "model_version":        "test-v1",
}


@pytest.mark.integration
def test_live_ingest_and_query():
    """Ingest one event and verify it appears in the audit trail."""
    # Step 1 — ingest
    r = requests.post(
        f"{DETECTOR_URL}/api/v1/events",
        json=TEST_EVENT,
        timeout=10,
    )
    assert r.status_code == 200, f"Ingest failed: {r.status_code} {r.text}"
    ingest_data = r.json()
    event_id = ingest_data.get("event_id")
    assert event_id, f"Ingest response missing event_id: {ingest_data}"

    # Step 2 — poll audit-api until record appears (up to 30 s)
    records = []
    deadline = time.time() + 30
    while time.time() < deadline:
        r = requests.post(
            f"{AUDIT_URL}/api/v1/audit/trail",
            json={"asset_id": TEST_EVENT["asset_id"], "page_size": 5},
            timeout=10,
        )
        assert r.status_code == 200, f"Audit query error: {r.status_code} {r.text}"
        records = r.json()
        if records:
            break
        time.sleep(1)

    assert records, (
        f"Audit trail returned [] for asset_id={TEST_EVENT['asset_id']} after 30 s. "
        "The blockchain-logger may not have committed the event to Fabric+Redis."
    )

    # Step 3 — verify fields match original event
    rec = records[0]
    assert rec["asset_id"]       == TEST_EVENT["asset_id"]
    assert rec["severity"]       == TEST_EVENT["severity"]
    assert rec["attack_category"] == TEST_EVENT["attack_category"]
    assert rec["ipfs_cid"],       "Record missing ipfs_cid — IPFS pin did not happen"
    assert rec["sha256"],         "Record missing sha256"
    assert rec["tx_id"],          "Record missing tx_id — Fabric commit did not happen"

    # Step 4 — call verify endpoint, expect VALID
    stored_event_id = str(rec.get("event_id", event_id))
    r = requests.get(
        f"{AUDIT_URL}/api/v1/verify/{stored_event_id}",
        timeout=30,
    )
    assert r.status_code == 200, f"Verify endpoint error: {r.status_code} {r.text}"
    result = r.json()
    status = result.get("status")
    assert status == "VALID", (
        f"Integrity verification returned status={status!r} (detail: {result.get('detail')}). "
        "Expected VALID — check IPFS availability and ECDSA key paths."
    )
