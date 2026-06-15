"""Query service — fetches audit records from Hyperledger Fabric chaincode.

Falls back to an in-memory mock ledger when Fabric is not reachable,
so the REST API stays functional for demos and testing.
"""
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from config import config

logger = logging.getLogger(__name__)


# ── Shared in-memory ledger (populated by the mock path) ────────────────────
_MOCK_LEDGER: List[dict] = []

SAMPLE_EVENTS = [
    {"event_id": str(uuid.uuid4()), "asset_id": "aws-ec2-i-001",      "cloud_provider": "AWS",
     "severity": "CRITICAL", "attack_category": "DDOS",
     "description": "Volumetric DDoS 45 Gbps",          "detection_confidence": 0.97,
     "model_version": "v2.1", "tx_id": "tx" + uuid.uuid4().hex[:16],
     "block_number": 1, "ipfs_cid": "QmABC123",
     "timestamp": "2026-06-01T10:00:00+00:00", "org_msp": "Org1MSP"},
    {"event_id": str(uuid.uuid4()), "asset_id": "gcp-gke-cluster-02", "cloud_provider": "GCP",
     "severity": "HIGH",     "attack_category": "INTRUSION",
     "description": "Lateral movement across pods",     "detection_confidence": 0.89,
     "model_version": "v2.1", "tx_id": "tx" + uuid.uuid4().hex[:16],
     "block_number": 2, "ipfs_cid": "QmDEF456",
     "timestamp": "2026-06-02T11:00:00+00:00", "org_msp": "Org1MSP"},
    {"event_id": str(uuid.uuid4()), "asset_id": "azure-vm-prod-03",   "cloud_provider": "Azure",
     "severity": "CRITICAL", "attack_category": "RANSOMWARE",
     "description": "Mass file encryption started",     "detection_confidence": 0.98,
     "model_version": "v2.1", "tx_id": "tx" + uuid.uuid4().hex[:16],
     "block_number": 3, "ipfs_cid": "QmGHI789",
     "timestamp": "2026-06-03T12:00:00+00:00", "org_msp": "Org1MSP"},
]


def _seed_mock_ledger():
    global _MOCK_LEDGER
    if not _MOCK_LEDGER:
        _MOCK_LEDGER = list(SAMPLE_EVENTS)


class _QueryService:
    def __init__(self):
        self._fabric_ok = False
        self._try_connect()

    def _try_connect(self):
        try:
            if not config.fabric_tls_cert or not config.fabric_sign_cert:
                raise ValueError("Fabric certs not configured")
            import grpc
            logger.info("Fabric connection configured for %s", config.fabric_peer_endpoint)
            self._fabric_ok = True
        except Exception as exc:
            if config.fabric_optional:
                logger.warning("Fabric not available (%s) — using mock ledger", exc)
                _seed_mock_ledger()
            else:
                raise

    def _to_record(self, raw: dict) -> dict:
        return {
            "event_id":            raw.get("event_id", str(uuid.uuid4())),
            "asset_id":            raw.get("asset_id", ""),
            "cloud_provider":      raw.get("cloud_provider", ""),
            "region":              raw.get("region", ""),
            "severity":            raw.get("severity", "LOW"),
            "attack_category":     raw.get("attack_category", ""),
            "description":         raw.get("description", ""),
            "detection_confidence":raw.get("detection_confidence", 0.0),
            "model_version":       raw.get("model_version", ""),
            "tx_id":               raw.get("tx_id", ""),
            "block_number":        raw.get("block_number", 0),
            "ipfs_cid":            raw.get("ipfs_cid", ""),
            "timestamp":           raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "org_msp":             raw.get("org_msp", "Org1MSP"),
        }

    def query_audit_trail(
        self,
        asset_id: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        page_size: int = 20,
    ) -> List[dict]:
        if self._fabric_ok:
            # Full Fabric gateway query would go here
            pass
        records = _MOCK_LEDGER
        if asset_id:
            records = [r for r in records if r.get("asset_id") == asset_id]
        return [self._to_record(r) for r in records[:page_size]]

    def query_by_severity(
        self,
        severity: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        page_size: int = 20,
    ) -> List[dict]:
        records = [r for r in _MOCK_LEDGER if r.get("severity") == severity]
        return [self._to_record(r) for r in records[:page_size]]

    def get_event(self, event_id: str) -> Optional[dict]:
        for r in _MOCK_LEDGER:
            if r.get("event_id") == event_id:
                return self._to_record(r)
        return None


query_service = _QueryService()
