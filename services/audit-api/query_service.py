"""
services/audit-api/query_service.py

All query helpers read from the shared Redis instance that the
blockchain-logger writes to after every successful Fabric commit.

No _MOCK_LEDGER, no in-process state, no simulation paths.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from typing import List, Optional

# Make shared/ importable
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import redis  # type: ignore

from shared import config as cfg
from shared.event_schema import SecurityEvent, VerificationResult, VerificationStatus
from shared.ipfs_client import IPFSError, fetch_and_verify

log = logging.getLogger(__name__)

_redis: Optional[redis.Redis] = None


def _get_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.from_url(cfg.REDIS_URL, decode_responses=True)
    return _redis


# ─────────────────────────────────────────────────────────────────────────
def _get_record(event_id: str) -> Optional[SecurityEvent]:
    """Fetch one record from Redis by event_id. Returns None if not found."""
    raw = _get_redis().get(cfg.REDIS_KEY_PREFIX + event_id)
    if raw is None:
        return None
    try:
        return SecurityEvent.from_ledger_dict(json.loads(raw))
    except Exception as exc:
        log.error("Failed to deserialise event_id=%s: %s", event_id, exc)
        return None


def _get_event_ids_for_asset(asset_id: str, limit: int = 100) -> List[str]:
    """Return up to *limit* event_ids for an asset, newest first."""
    return _get_redis().zrevrange(
        cfg.REDIS_IDX_ASSET + asset_id, 0, limit - 1
    )


def _get_event_ids_for_severity(severity: str, limit: int = 100) -> List[str]:
    return _get_redis().zrevrange(
        cfg.REDIS_IDX_SEV + severity, 0, limit - 1
    )


# ── Public query API ─────────────────────────────────────────────────────────────

def query_by_asset(asset_id: str, page_size: int = 20) -> List[SecurityEvent]:
    """
    Return up to *page_size* audit records for the given asset_id,
    ordered newest-first.  Returns [] if the asset has no records.
    """
    ids = _get_event_ids_for_asset(asset_id, limit=page_size)
    records = []
    for eid in ids:
        rec = _get_record(eid)
        if rec is not None:
            records.append(rec)
    log.info("query_by_asset asset=%s found=%d", asset_id, len(records))
    return records


def query_by_severity(severity: str, page_size: int = 100) -> List[SecurityEvent]:
    """
    Return up to *page_size* audit records for the given severity level.
    """
    ids = _get_event_ids_for_severity(severity, limit=page_size)
    records = []
    for eid in ids:
        rec = _get_record(eid)
        if rec is not None:
            records.append(rec)
    log.info("query_by_severity severity=%s found=%d", severity, len(records))
    return records


def query_by_event_id(event_id: str) -> Optional[SecurityEvent]:
    """Return a single record by its event_id, or None."""
    return _get_record(event_id)


# ── Integrity verification ───────────────────────────────────────────────────────────

def verify_record(event_id: str) -> VerificationResult:
    """
    Full integrity check for a stored audit record.

    Checks (in order):
      1. Record exists in Redis with all required ledger fields.
      2. On-chain SHA-256 matches a fresh recomputation over canonical fields.
      3. Live IPFS payload SHA-256 matches the stored hash.
      4. ECDSA agent_signature over canonical_bytes() is valid.

    Returns VerificationResult with an explicit status enum value.
    """
    rec = _get_record(event_id)
    if rec is None:
        return VerificationResult(
            event_id=event_id,
            status=VerificationStatus.CID_NOT_FOUND,
            detail="Record not found in Redis cache",
        )

    # ─ Check required ledger fields ─────────────────────────────────────────────
    missing = [f for f in ("ipfs_cid", "sha256", "agent_signature") if not getattr(rec, f, None)]
    if missing:
        return VerificationResult(
            event_id=event_id,
            status=VerificationStatus.MISSING_FIELDS,
            detail=f"Missing ledger fields: {missing}",
        )

    recomputed = rec.compute_sha256()
    on_chain_hash = rec.sha256

    # ─ 1. On-chain hash vs fresh recomputation ──────────────────────────────
    if on_chain_hash != recomputed:
        return VerificationResult(
            event_id=event_id,
            status=VerificationStatus.HASH_MISMATCH,
            on_chain_hash=on_chain_hash,
            recomputed_hash=recomputed,
            detail="SHA-256 over canonical fields does not match stored hash",
        )

    # ─ 2. Fetch live IPFS payload and verify hash ───────────────────────────
    try:
        ipfs_ok = fetch_and_verify(rec.ipfs_cid, on_chain_hash)
    except IPFSError as exc:
        return VerificationResult(
            event_id=event_id,
            status=VerificationStatus.CID_NOT_FOUND,
            on_chain_hash=on_chain_hash,
            recomputed_hash=recomputed,
            detail=f"IPFS fetch failed: {exc}",
        )

    if not ipfs_ok:
        return VerificationResult(
            event_id=event_id,
            status=VerificationStatus.IPFS_HASH_MISMATCH,
            on_chain_hash=on_chain_hash,
            recomputed_hash=recomputed,
            detail="Live IPFS payload hash differs from on-chain hash",
        )

    # ─ 3. ECDSA signature ──────────────────────────────────────────────────────
    sig_valid = _verify_signature(rec)
    if not sig_valid:
        return VerificationResult(
            event_id=event_id,
            status=VerificationStatus.SIGNATURE_INVALID,
            on_chain_hash=on_chain_hash,
            recomputed_hash=recomputed,
            ipfs_hash=on_chain_hash,  # IPFS matched
            signature_valid=False,
            detail="ECDSA agent signature verification failed",
        )

    return VerificationResult(
        event_id=event_id,
        status=VerificationStatus.VALID,
        on_chain_hash=on_chain_hash,
        recomputed_hash=recomputed,
        ipfs_hash=on_chain_hash,
        signature_valid=True,
        detail="All checks passed",
    )


def _verify_signature(rec: SecurityEvent) -> bool:
    """
    Verify the ECDSA P-256 agent_signature over canonical_bytes().
    Loads the agent cert from disk (AGENT_CERT_PATH).
    Returns False on any error so callers always get a bool.
    """
    if not rec.agent_signature or not rec.agent_identity:
        return False
    try:
        from cryptography.hazmat.primitives import hashes, serialization  # type: ignore
        from cryptography.hazmat.primitives.asymmetric import ec  # type: ignore
        from cryptography import x509  # type: ignore
        from cryptography.hazmat.backends import default_backend  # type: ignore
        from cryptography.exceptions import InvalidSignature  # type: ignore

        with open(cfg.AGENT_CERT_PATH, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        pub_key = cert.public_key()

        sig_bytes = bytes.fromhex(rec.agent_signature)
        pub_key.verify(sig_bytes, rec.canonical_bytes(), ec.ECDSA(hashes.SHA256()))  # type: ignore
        return True
    except (InvalidSignature, Exception) as exc:
        log.warning("Signature verify failed for event_id=%s: %s", rec.event_id, exc)
        return False
