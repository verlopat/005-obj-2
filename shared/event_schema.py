"""
shared/event_schema.py  —  Canonical Pydantic v2 event model.

Imported by:
  - services/detector-adapter   (validates inbound HTTP body)
  - services/blockchain-logger  (validates Kafka message before signing)
  - services/audit-api          (validates records returned from Redis/Fabric)

Using one schema ensures the SHA-256 canonical payload never drifts
between services.  Any field addition/removal must be done here first.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


class Severity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class CloudProvider(str, Enum):
    AWS   = "AWS"
    GCP   = "GCP"
    AZURE = "Azure"
    OTHER = "OTHER"


# Fields that are excluded from the canonical SHA-256 digest because they
# are assigned by the ledger layer, not by the event producer.
_DIGEST_SKIP = frozenset({
    "tx_id", "block_number", "ipfs_cid", "sha256",
    "org_msp", "agent_signature", "agent_identity",
})


class SecurityEvent(BaseModel):
    """Canonical security event — source of truth for all three services."""

    # ── Identity ─────────────────────────────────────────────────────────────
    event_id:   UUID     = Field(default_factory=uuid4)
    asset_id:   str      = Field(..., min_length=1, max_length=256)
    cloud_provider: CloudProvider
    region:     str      = Field(default="", max_length=64)

    # ── Detection ─────────────────────────────────────────────────────────────
    severity:             Severity
    attack_category:      str   = Field(..., min_length=1, max_length=128)
    description:          str   = Field(default="", max_length=2048)
    detection_confidence: float = Field(ge=0.0, le=1.0)
    model_version:        str   = Field(default="", max_length=64)

    # ── Timing ───────────────────────────────────────────────────────────────
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # ── Ledger fields (set by logger after commit) ───────────────────────────
    tx_id:        Optional[str]  = None
    block_number: Optional[int]  = None
    ipfs_cid:     Optional[str]  = None
    sha256:       Optional[str]  = None
    org_msp:      Optional[str]  = None

    # ── PKI ──────────────────────────────────────────────────────────────────
    agent_identity:  Optional[str] = None
    agent_signature: Optional[str] = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def _parse_ts(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        raise ValueError(f"Cannot parse timestamp: {v!r}")

    @model_validator(mode="after")
    def _ensure_utc(self) -> "SecurityEvent":
        ts = self.timestamp
        if ts.tzinfo is None:
            self.timestamp = ts.replace(tzinfo=timezone.utc)
        return self

    # ── Canonical serialisation ───────────────────────────────────────────────

    def canonical_dict(self) -> Dict[str, Any]:
        """
        Deterministic dict of all fields that enter the SHA-256 digest.
        Ledger-assigned fields (tx_id, block_number, ipfs_cid, sha256,
        org_msp, agent_signature, agent_identity) are excluded so that
        the digest can be recomputed before and after commit and still match.
        """
        full = self.model_dump(mode="json")
        return {k: v for k, v in sorted(full.items()) if k not in _DIGEST_SKIP}

    def canonical_bytes(self) -> bytes:
        """UTF-8 encoded canonical JSON — what gets SHA-256 hashed and signed."""
        return json.dumps(
            self.canonical_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def compute_sha256(self) -> str:
        """Return hex SHA-256 over canonical_bytes()."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def verify_sha256(self) -> bool:
        """
        Return True if the stored sha256 field matches a fresh recomputation.
        Always returns False if sha256 is not set.
        """
        if not self.sha256:
            return False
        return self.sha256 == self.compute_sha256()

    def to_ledger_dict(self) -> Dict[str, Any]:
        """Full dict for Redis/ledger storage (includes ledger fields)."""
        return self.model_dump(mode="json")

    @classmethod
    def from_kafka_bytes(cls, raw: bytes) -> "SecurityEvent":
        """Deserialise a Kafka message value."""
        return cls.model_validate_json(raw)

    @classmethod
    def from_ledger_dict(cls, d: Dict[str, Any]) -> "SecurityEvent":
        """Reconstruct from a Redis/Fabric record dict."""
        return cls.model_validate(d)


class VerificationStatus(str, Enum):
    VALID              = "VALID"
    HASH_MISMATCH      = "HASH_MISMATCH"
    SIGNATURE_INVALID  = "SIGNATURE_INVALID"
    CID_NOT_FOUND      = "CID_NOT_FOUND"
    IPFS_HASH_MISMATCH = "IPFS_HASH_MISMATCH"
    MISSING_FIELDS     = "MISSING_FIELDS"


class VerificationResult(BaseModel):
    event_id:         str
    status:           VerificationStatus
    on_chain_hash:    Optional[str] = None
    recomputed_hash:  Optional[str] = None
    ipfs_hash:        Optional[str] = None
    signature_valid:  Optional[bool] = None
    detail:           str = ""
