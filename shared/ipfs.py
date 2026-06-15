"""Real IPFS add + pin via the Kubo HTTP API.

Returns the CID returned by the daemon — not a derived stub.
Verification fetches the stored object and recomputes SHA-256.
"""
from __future__ import annotations

import hashlib
import io
import logging

import requests

log = logging.getLogger(__name__)


def add_and_pin(data: bytes, ipfs_api: str) -> str:
    """Upload *data* to IPFS, pin it, and return the real CID string.

    Raises RuntimeError on any failure so the caller can route to DLQ.
    """
    # 1. Add
    resp = requests.post(
        f"{ipfs_api}/api/v0/add",
        files={"file": ("payload", io.BytesIO(data), "application/octet-stream")},
        params={"pin": "true", "cid-version": "1"},
        timeout=30,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"IPFS add failed {resp.status_code}: {resp.text[:200]}")
    cid = resp.json().get("Hash")
    if not cid:
        raise RuntimeError(f"IPFS add returned no Hash: {resp.text[:200]}")

    # 2. Explicit pin (belt-and-suspenders — add --pin=true already pins,
    #    but an explicit pin call ensures it survives GC)
    pin_resp = requests.post(
        f"{ipfs_api}/api/v0/pin/add",
        params={"arg": cid},
        timeout=30,
    )
    if pin_resp.status_code != 200:
        log.warning("IPFS pin/add returned %d for CID %s — continuing",
                    pin_resp.status_code, cid)

    log.info("[IPFS] pinned CID=%s (%d bytes)", cid, len(data))
    return cid


def fetch_and_verify(cid: str, expected_sha256: str, ipfs_api: str) -> bool:
    """Fetch the object at *cid* and verify its SHA-256 matches *expected_sha256*.

    Returns True on match, False on mismatch or fetch failure.
    """
    try:
        resp = requests.post(
            f"{ipfs_api}/api/v0/cat",
            params={"arg": cid},
            timeout=30,
        )
        if resp.status_code != 200:
            log.warning("[IPFS] cat %s returned %d", cid, resp.status_code)
            return False
        actual = hashlib.sha256(resp.content).hexdigest()
        if actual != expected_sha256:
            log.warning("[IPFS] hash mismatch CID=%s expected=%s actual=%s",
                        cid, expected_sha256, actual)
            return False
        return True
    except Exception as exc:
        log.warning("[IPFS] fetch_and_verify error: %s", exc)
        return False
