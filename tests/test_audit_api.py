"""Tests for the audit-api query and report service."""
import json
import sys
import os
import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'services', 'audit-api'))

from schemas import (
    ComplianceReport, ComplianceStandard, EventRecord,
    IntegrityCheckResult,
)

# --- EventRecord schema validation ---

def make_event(**kwargs):
    defaults = {
        "event_id": "evt-001", "asset_id": "asset-123",
        "severity": "HIGH", "attack_category": "DDOS",
        "description": "Test event", "ipfs_cid": "bafybei123",
        "sha256": "abc123", "tx_id": "txid-001",
        "timestamp": datetime.utcnow().isoformat(),
        "detection_confidence": 0.95, "model_version": "v1.0",
        "logged_by_msp": "Org1MSP",
    }
    defaults.update(kwargs)
    return EventRecord(**defaults)

def test_event_record_valid():
    e = make_event()
    assert e.event_id == "evt-001"
    assert e.severity == "HIGH"

def test_event_record_optional_fields():
    e = make_event()
    assert e.block_number is None
    assert e.signature is None

def test_compliance_report_structure():
    events = [make_event(severity="HIGH"), make_event(event_id="evt-002", severity="CRITICAL")]
    report = ComplianceReport(
        standard="ISO-27001",
        generated_at=datetime.utcnow(),
        period_start=datetime.utcnow() - timedelta(days=1),
        period_end=datetime.utcnow(),
        total_events=2,
        events_by_severity={"HIGH": 1, "CRITICAL": 1},
        events_by_category={"DDOS": 2},
        high_confidence_events=2,
        integrity_violations=0,
        events=events,
        report_sha256="deadbeef",
    )
    assert report.total_events == 2
    assert report.events_by_severity["HIGH"] == 1
    assert len(report.events) == 2

def test_integrity_check_result_match():
    result = IntegrityCheckResult(
        event_id="evt-001",
        chain_sha256="abc123",
        ipfs_sha256="abc123",
        match=True,
        ipfs_cid="bafybei123",
        verified_at=datetime.utcnow(),
    )
    assert result.match is True

def test_integrity_check_result_mismatch():
    result = IntegrityCheckResult(
        event_id="evt-002",
        chain_sha256="abc123",
        ipfs_sha256="different456",
        match=False,
        ipfs_cid="bafybei456",
        verified_at=datetime.utcnow(),
    )
    assert result.match is False
