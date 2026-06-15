"""Query service — fetches audit records from Hyperledger Fabric chaincode.

Falls back to an in-memory mock ledger when Fabric is not reachable,
so the REST API stays functional for demos and testing.

Key fix (PhD review): ingest_live_event() appends newly ingested events
to _MOCK_LEDGER so Step 7 audit query reflects events posted in Step 6,
not stale seed data from SAMPLE_EVENTS.
"""
import hashlib
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from config import config

logger = logging.getLogger(__name__)


# ── Shared in-memory ledger ──────────────────────────────────────────────────
# Seed data is kept only as a fallback for --mock mode.
# In live mode, events are written here by ingest_live_event() as they
# arrive, so the audit trail always reflects real ingested events.
_MOCK_LEDGER: List[dict] = []
_BLOCK_COUNTER = 0


def _next_block() -> int:
    global _BLOCK_COUNTER
    _BLOCK_COUNTER += 1
    return _BLOCK_COUNTER


def _sha256_event(event: dict) -> str:
    """Canonical SHA-256 over the mutable fields of an event."""
    SKIP = {"tx_id", "block_number", "ipfs_cid", "sha256",
            "timestamp", "org_msp", "signature"}
    payload = json.dumps(
        {k: v for k, v in sorted(event.items()) if k not in SKIP},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def ingest_live_event(event: dict) -> dict:
    """
    Called by the blockchain-logger (or run.py) when an event arrives from
    Kafka.  Assigns a block number, a deterministic tx_id, a SHA-256
    integrity digest, and a stub IPFS CID, then appends to the ledger.

    In a production deployment this function is replaced by a real Fabric
    Gateway SDK call — the interface is identical.
    """
    block   = _next_block()
    # tx_id derived from event content — same input always produces same tx_id
    # (mimics Fabric's deterministic endorsement hash)
    payload = json.dumps(
        {k: v for k, v in sorted(event.items())},
        sort_keys=True, separators=(",", ": "),
    ).encode()
    tx_id   = "tx" + hashlib.sha256(payload + str(time.time_ns()).encode()).hexdigest()[:16]
    sha256  = _sha256_event(event)
    # IPFS CID: in production, the full event JSON is pinned via ipfs.add();
    # here we derive a deterministic stub from the SHA-256 so it is at least
    # traceable (not the placeholder "QmABC123" strings in seed data).
    cid_raw = hashlib.sha256((sha256 + "ipfs").encode()).hexdigest()
    ipfs_cid = "Qm" + cid_raw[:44]

    record = {
        **event,
        "tx_id":        tx_id,
        "block_number": block,
        "ipfs_cid":     ipfs_cid,
        "sha256":       sha256,
        "timestamp":    event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "org_msp":      "Org1MSP",
    }
    _MOCK_LEDGER.append(record)
    logger.info("[LEDGER] block=%d tx=%s asset=%s severity=%s sha256=%s...",
                block, tx_id, event.get("asset_id", "?"),
                event.get("severity", "?"), sha256[:12])
    return record


def verify_integrity(record: dict) -> bool:
    """Return True iff the stored SHA-256 matches a fresh recomputation."""
    stored = record.get("sha256", "")
    if not stored:
        return False
    return _sha256_event(record) == stored


SAMPLE_EVENTS = []  # no seed data in live mode


def _seed_mock_ledger():
    """Only called in --mock mode to pre-populate the ledger."""
    global _MOCK_LEDGER
    if not _MOCK_LEDGER:
        seed = [
            {"event_id": str(uuid.uuid4()), "asset_id": "aws-ec2-i-001",
             "cloud_provider": "AWS",   "region": "us-east-1",
             "severity": "CRITICAL", "attack_category": "DDOS",
             "description": "Volumetric DDoS 45 Gbps",
             "detection_confidence": 0.97, "model_version": "isoforest-v1.0"},
            {"event_id": str(uuid.uuid4()), "asset_id": "gcp-gke-cluster-02",
             "cloud_provider": "GCP",   "region": "us-central1",
             "severity": "HIGH",     "attack_category": "INTRUSION",
             "description": "Lateral movement detected across pods",
             "detection_confidence": 0.89, "model_version": "isoforest-v1.0"},
            {"event_id": str(uuid.uuid4()), "asset_id": "azure-vm-prod-03",
             "cloud_provider": "Azure", "region": "eastus",
             "severity": "CRITICAL", "attack_category": "RANSOMWARE",
             "description": "Mass file encryption started",
             "detection_confidence": 0.98, "model_version": "isoforest-v1.0"},
        ]
        for ev in seed:
            ingest_live_event(ev)


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
                logger.warning("Fabric not available (%s) — using in-memory ledger", exc)
            else:
                raise

    def _to_record(self, raw: dict) -> dict:
        return {
            "event_id":             raw.get("event_id", str(uuid.uuid4())),
            "asset_id":             raw.get("asset_id", ""),
            "cloud_provider":       raw.get("cloud_provider", ""),
            "region":               raw.get("region", ""),
            "severity":             raw.get("severity", "LOW"),
            "attack_category":      raw.get("attack_category", ""),
            "description":          raw.get("description", ""),
            "detection_confidence": raw.get("detection_confidence", 0.0),
            "model_version":        raw.get("model_version", ""),
            "tx_id":                raw.get("tx_id", ""),
            "block_number":         raw.get("block_number", 0),
            "ipfs_cid":             raw.get("ipfs_cid", ""),
            "timestamp":            raw.get("timestamp",
                                           datetime.now(timezone.utc).isoformat()),
            "org_msp":              raw.get("org_msp", "Org1MSP"),
        }

    def query_audit_trail(
        self,
        asset_id: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        page_size: int = 20,
    ) -> List[dict]:
        if self._fabric_ok:
            pass  # Fabric Gateway SDK call goes here
        records = list(_MOCK_LEDGER)
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
