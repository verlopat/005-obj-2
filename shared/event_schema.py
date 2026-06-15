"""Single source of truth for the SecurityEvent schema.

Used by detector-adapter, blockchain-logger, and audit-api.
All three services import from here — no drift possible.
"""
from __future__ import annotations

import hashlib
import json
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

SEVERITY = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
ATTACK_CATEGORY = Literal[
    "DDOS", "INTRUSION", "RECON", "DATA_EXFIL",
    "ANOMALY", "RANSOMWARE", "CREDENTIAL_STUFFING", "OTHER",
]


class SecurityEvent(BaseModel):
    """Inbound event — produced by detector-adapter, consumed by blockchain-logger."""
    event_id: str = Field(..., min_length=1)
    asset_id: str = Field(..., min_length=1)
    cloud_provider: str = Field(..., min_length=1)
    region: str = Field(..., min_length=1)
    severity: SEVERITY
    attack_category: ATTACK_CATEGORY
    description: str = Field(..., min_length=1)
    detection_confidence: float = Field(..., ge=0.0, le=1.0)
    model_version: str = Field(..., min_length=1)
    timestamp: Optional[str] = None

    @field_validator("detection_confidence")
    @classmethod
    def confidence_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("detection_confidence must be in [0, 1]")
        return round(v, 6)


class AuditRecord(BaseModel):
    """What the blockchain-logger writes to Fabric and the audit-api returns."""
    event_id: str
    asset_id: str
    cloud_provider: str
    region: str
    severity: SEVERITY
    attack_category: ATTACK_CATEGORY
    description: str
    detection_confidence: float
    model_version: str
    timestamp: str
    tx_id: str
    block_number: int
    ipfs_cid: str
    sha256: str
    org_msp: str
    signature: str


# ── Canonical hash helpers ──────────────────────────────────────────────────

# Fields included in the canonical payload for SHA-256 and signing.
# These must never change — doing so would invalidate all stored hashes.
_CANONICAL_FIELDS = [
    "event_id", "asset_id", "cloud_provider", "region",
    "severity", "attack_category", "description",
    "detection_confidence", "model_version", "timestamp",
]


def canonical_payload(event: dict) -> bytes:
    """Return the canonical JSON bytes that are hashed and signed."""
    subset = {k: event[k] for k in _CANONICAL_FIELDS if k in event}
    return json.dumps(subset, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_of(event: dict) -> str:
    """SHA-256 hex digest over canonical_payload(event)."""
    return hashlib.sha256(canonical_payload(event)).hexdigest()
