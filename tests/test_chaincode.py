"""Unit tests for the security_logger chaincode logic (Python mock)."""
import json
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

# --- Mock Fabric stub for chaincode testing ---
class MockStub:
    def __init__(self):
        self._state = {}
        self.events = []

    def GetState(self, key):
        return json.dumps(self._state.get(key)).encode() if key in self._state else None

    def PutState(self, key, value):
        self._state[key] = json.loads(value)

    def SetEvent(self, name, payload):
        self.events.append({"name": name, "payload": json.loads(payload)})

    def GetCreator(self):
        return b"\x00" * 10 + b"Org1MSP" + b"\x00" * 10

    def CreateCompositeKey(self, prefix, parts):
        return "~".join([prefix] + parts)


class MockSecurityEvent:
    """Simulates the chaincode LogSecurityEvent logic."""
    def log_event(self, stub: MockStub, event_id, asset_id, severity, description,
                  ipfs_cid, sha256, attack_category, detection_confidence, model_version,
                  signature, timestamp):
        if not event_id or not asset_id:
            raise ValueError("event_id and asset_id are required")
        if severity not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            raise ValueError(f"Invalid severity: {severity}")
        event = {
            "event_id": event_id, "asset_id": asset_id, "severity": severity,
            "description": description, "ipfs_cid": ipfs_cid, "sha256": sha256,
            "attack_category": attack_category,
            "detection_confidence": float(detection_confidence),
            "model_version": model_version, "signature": signature,
            "timestamp": timestamp, "logged_by": "Org1MSP",
        }
        stub.PutState(event_id, json.dumps(event).encode())
        stub.SetEvent("SecurityEventLogged", json.dumps({"event_id": event_id, "severity": severity}).encode())
        return event_id

    def get_event(self, stub: MockStub, event_id):
        raw = stub.GetState(event_id)
        if raw is None:
            return None
        return json.loads(raw)


@pytest.fixture
def stub():
    return MockStub()

@pytest.fixture
def chaincode():
    return MockSecurityEvent()


def test_log_event_success(stub, chaincode):
    tx_id = chaincode.log_event(
        stub, "evt-001", "asset-123", "CRITICAL",
        "DDoS attack detected", "bafybeiabc123", "sha256abc",
        "DDOS", "0.95", "v1.0", "sig123",
        datetime.now(timezone.utc).isoformat()
    )
    assert tx_id == "evt-001"

def test_log_event_stored(stub, chaincode):
    chaincode.log_event(stub, "evt-002", "asset-456", "HIGH",
                        "Intrusion attempt", "bafybei456", "sha256def",
                        "INTRUSION", "0.80", "v1.0", "",
                        datetime.now(timezone.utc).isoformat())
    record = chaincode.get_event(stub, "evt-002")
    assert record is not None
    assert record["severity"] == "HIGH"
    assert record["asset_id"] == "asset-456"
    assert record["ipfs_cid"] == "bafybei456"

def test_log_event_emits_chaincode_event(stub, chaincode):
    chaincode.log_event(stub, "evt-003", "asset-789", "MEDIUM",
                        "Anomaly detected", "bafybei789", "sha256ghi",
                        "ANOMALY", "0.75", "v1.0", "",
                        datetime.now(timezone.utc).isoformat())
    assert len(stub.events) == 1
    assert stub.events[0]["name"] == "SecurityEventLogged"
    assert stub.events[0]["payload"]["event_id"] == "evt-003"

def test_invalid_severity_rejected(stub, chaincode):
    with pytest.raises(ValueError, match="Invalid severity"):
        chaincode.log_event(stub, "evt-004", "asset-001", "EXTREME",
                            "Test", "cid", "sha", "DDOS", "0.9", "v1.0", "",
                            datetime.now(timezone.utc).isoformat())

def test_missing_event_id_rejected(stub, chaincode):
    with pytest.raises(ValueError):
        chaincode.log_event(stub, "", "asset-001", "LOW",
                            "Test", "cid", "sha", "UNKNOWN", "0.5", "v1.0", "",
                            datetime.now(timezone.utc).isoformat())

def test_get_nonexistent_event_returns_none(stub, chaincode):
    result = chaincode.get_event(stub, "nonexistent")
    assert result is None

def test_detection_confidence_stored_as_float(stub, chaincode):
    chaincode.log_event(stub, "evt-005", "asset-001", "LOW",
                        "Test", "cid", "sha", "UNKNOWN", "0.73", "v1.0", "",
                        datetime.now(timezone.utc).isoformat())
    record = chaincode.get_event(stub, "evt-005")
    assert isinstance(record["detection_confidence"], float)
    assert record["detection_confidence"] == 0.73
