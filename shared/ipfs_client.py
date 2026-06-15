"""
shared/ipfs_client.py  —  Real IPFS HTTP-API client.

Does NOT use stub / in-memory CIDs.  Every call goes to the live IPFS daemon.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Tuple

import requests

from shared.config import IPFS_API_URL, IPFS_PIN, IPFS_TIMEOUT_S

log = logging.getLogger(__name__)


class IPFSError(RuntimeError):
    pass


def add_and_pin(payload_bytes: bytes) -> Tuple[str, str]:
    """
    Upload *payload_bytes* to IPFS, optionally pin it, and return
    (cid, sha256_hex) where sha256_hex is the SHA-256 digest of *payload_bytes*.

    Raises IPFSError on any failure.
    """
    local_sha256 = hashlib.sha256(payload_bytes).hexdigest()

    # ─ Add via /api/v0/add?pin=false first; we pin explicitly below ───────────
    try:
        resp = requests.post(
            f"{IPFS_API_URL}/api/v0/add",
            files={"file": ("payload.json", payload_bytes, "application/json")},
            params={"pin": "false", "hash": "sha2-256"},
            timeout=IPFS_TIMEOUT_S,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise IPFSError(f"IPFS add failed: {exc}") from exc

    data = resp.json()
    cid: str = data.get("Hash", "")
    if not cid:
        raise IPFSError(f"IPFS add returned no CID: {data}")

    # ─ Pin ───────────────────────────────────────────────────────────────────
    if IPFS_PIN:
        try:
            pin_resp = requests.post(
                f"{IPFS_API_URL}/api/v0/pin/add",
                params={"arg": cid},
                timeout=IPFS_TIMEOUT_S,
            )
            pin_resp.raise_for_status()
            log.debug("Pinned CID %s", cid)
        except requests.RequestException as exc:
            raise IPFSError(f"IPFS pin failed for CID {cid}: {exc}") from exc

    log.info("IPFS add OK  cid=%s  sha256=%s", cid, local_sha256)
    return cid, local_sha256


def fetch_and_verify(cid: str, expected_sha256: str) -> bool:
    """
    Fetch the object at *cid* from IPFS, recompute its SHA-256, and
    return True only if it matches *expected_sha256*.

    Raises IPFSError if the CID cannot be fetched.
    """
    try:
        resp = requests.post(
            f"{IPFS_API_URL}/api/v0/cat",
            params={"arg": cid},
            timeout=IPFS_TIMEOUT_S,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise IPFSError(f"IPFS cat failed for CID {cid}: {exc}") from exc

    actual = hashlib.sha256(resp.content).hexdigest()
    if actual != expected_sha256:
        log.warning(
            "IPFS hash mismatch for CID %s: expected=%s actual=%s",
            cid, expected_sha256, actual,
        )
        return False

    log.debug("IPFS verify OK  cid=%s", cid)
    return True


def is_pinned(cid: str) -> bool:
    """Return True if *cid* is currently pinned on this IPFS node."""
    try:
        resp = requests.post(
            f"{IPFS_API_URL}/api/v0/pin/ls",
            params={"arg": cid, "type": "recursive"},
            timeout=IPFS_TIMEOUT_S,
        )
        if resp.status_code == 500:
            # IPFS returns 500 when the CID is not pinned
            return False
        resp.raise_for_status()
        keys = resp.json().get("Keys", {})
        return cid in keys
    except requests.RequestException:
        return False
