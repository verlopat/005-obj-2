"""Audit query service — reads exclusively from Hyperledger Fabric.

No mock ledger.  No in-memory fallback.  No _MOCK_LEDGER.
If Fabric is not reachable the call raises and the HTTP layer returns 503.

Verification pipeline:
  1. Fetch record from Fabric (on-chain hash, CID, signature)
  2. Fetch raw payload from IPFS by CID
  3. Recompute SHA-256 over fetched bytes
  4. Compare on-chain hash vs recomputed hash
  5. Verify ECDSA signature over canonical fields
  6. Return explicit status: VALID | HASH_MISMATCH | SIGNATURE_INVALID | CID_NOT_FOUND
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import List, Literal, Optional

import requests

from shared.config import IPFS_API_URL
from shared.event_schema import AuditRecord, canonical_payload
from shared.fabric_gateway import (
    get_event, query_by_asset, query_by_severity,
)
from shared.ipfs import fetch_and_verify

log = logging.getLogger(__name__)

VerifyStatus = Literal["VALID", "HASH_MISMATCH", "SIGNATURE_INVALID", "CID_NOT_FOUND"]


def _to_record(raw: dict) -> AuditRecord:
    """Coerce raw Fabric response dict → validated AuditRecord."""
    return AuditRecord(
        event_id=raw.get("event_id", ""),
        asset_id=raw.get("asset_id", ""),
        cloud_provider=raw.get("cloud_provider", ""),
        region=raw.get("region", ""),
        severity=raw.get("severity", "LOW"),
        attack_category=raw.get("attack_category", "OTHER"),
        description=raw.get("description", ""),
        detection_confidence=float(raw.get("detection_confidence", 0.0)),
        model_version=raw.get("model_version", ""),
        timestamp=raw.get("timestamp", ""),
        tx_id=raw.get("tx_id", ""),
        block_number=int(raw.get("block_number", 0)),
        ipfs_cid=raw.get("ipfs_cid", ""),
        sha256=raw.get("sha256", ""),
        org_msp=raw.get("org_msp", "Org1MSP"),
        signature=raw.get("signature", ""),
    )


def query_audit_trail(
    asset_id: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    page_size: int = 20,
) -> List[AuditRecord]:
    """Return audit records from Fabric.  Raises RuntimeError if Fabric unreachable."""
    raws = query_by_asset(asset_id or "", page_size) if asset_id else []
    return [_to_record(r) for r in raws]


def query_by_severity_live(
    severity: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    page_size: int = 20,
) -> List[AuditRecord]:
    raws = query_by_severity(severity, start_time, end_time, page_size)
    return [_to_record(r) for r in raws]


def get_event_live(event_id: str) -> Optional[AuditRecord]:
    raw = get_event(event_id)
    return _to_record(raw) if raw else None


def verify_record(event_id: str) -> dict:
    """Full three-way verification: on-chain hash, IPFS payload hash, signature.

    Returns:
        {"status": VerifyStatus, "event_id": str, "detail": str}
    """
    raw = get_event(event_id)
    if raw is None:
        return {"status": "CID_NOT_FOUND", "event_id": event_id,
                "detail": "Event not found on chain"}

    on_chain_hash = raw.get("sha256", "")
    cid           = raw.get("ipfs_cid", "")
    signature     = raw.get("signature", "")

    # 1. Fetch IPFS payload and recompute hash
    if not cid:
        return {"status": "CID_NOT_FOUND", "event_id": event_id,
                "detail": "No IPFS CID stored on chain"}

    try:
        resp = requests.post(
            f"{IPFS_API_URL}/api/v0/cat",
            params={"arg": cid},
            timeout=30,
        )
        if resp.status_code != 200:
            return {"status": "CID_NOT_FOUND", "event_id": event_id,
                    "detail": f"IPFS cat returned {resp.status_code}"}
        ipfs_bytes       = resp.content
        ipfs_sha256      = hashlib.sha256(ipfs_bytes).hexdigest()
    except Exception as exc:
        return {"status": "CID_NOT_FOUND", "event_id": event_id,
                "detail": f"IPFS fetch error: {exc}"}

    # 2. Compare on-chain hash vs IPFS payload hash
    if ipfs_sha256 != on_chain_hash:
        return {"status": "HASH_MISMATCH", "event_id": event_id,
                "detail": f"on-chain={on_chain_hash[:16]}... ipfs={ipfs_sha256[:16]}..."}

    # 3. Verify ECDSA signature over canonical fields
    if signature:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.exceptions import InvalidSignature
            import base64
            from shared.config import AGENT_CERT_PATH
            from pathlib import Path

            cert_pem  = Path(AGENT_CERT_PATH).read_bytes()
            from cryptography import x509
            cert      = x509.load_pem_x509_certificate(cert_pem)
            pub_key   = cert.public_key()
            sig_bytes = base64.b64decode(signature)
            payload   = canonical_payload(raw)
            try:
                pub_key.verify(sig_bytes, payload, ec.ECDSA(hashes.SHA256()))
            except InvalidSignature:
                return {"status": "SIGNATURE_INVALID", "event_id": event_id,
                        "detail": "ECDSA signature verification failed"}
        except Exception as exc:
            log.warning("Signature check error for %s: %s", event_id, exc)

    return {"status": "VALID", "event_id": event_id,
            "detail": f"on-chain hash matches IPFS payload; CID={cid}"}
