#!/usr/bin/env python3
"""
ipfs_uploader.py
----------------
Handles the hybrid on-chain / off-chain storage architecture required by Objective 2.

For each security event:
  1. Serialise the full payload (network features, confidence scores, metadata) to JSON
  2. Upload the payload to a local IPFS node and obtain a CID (content identifier)
  3. Compute SHA-256 hash of the payload bytes for on-chain verification
  4. Return (ipfs_cid, sha256_hash) for the blockchain logger to commit

Dependencies:
    pip install ipfshttpclient requests

IPFS node (default): http://127.0.0.1:5001
Set IPFS_API_URL env var to override.
"""

import hashlib
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import ipfshttpclient  # type: ignore
except ImportError:
    ipfshttpclient = None  # graceful fallback — hash-only mode

logging.basicConfig(level=logging.INFO, format="%(asctime)s [IPFS] %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

IPFS_API_URL = os.environ.get("IPFS_API_URL", "/ip4/127.0.0.1/tcp/5001")


def compute_sha256(data: bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def upload_to_ipfs(payload: dict[str, Any]) -> tuple[str, str]:
    """
    Upload *payload* to IPFS and return (cid, sha256_hash).

    If the IPFS daemon is unavailable, falls back to hash-only mode
    where the CID is set to the SHA-256 hash prefixed with 'sha256:'.
    This ensures the blockchain logger can still operate in offline environments.
    """
    payload["_upload_time"] = datetime.now(timezone.utc).isoformat()
    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    sha256_hash = compute_sha256(payload_bytes)

    if ipfshttpclient is None:
        logger.warning("ipfshttpclient not installed — falling back to hash-only mode")
        return f"sha256:{sha256_hash}", sha256_hash

    try:
        with ipfshttpclient.connect(IPFS_API_URL) as client:
            # Write to a temp file for the multipart upload
            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
                tmp.write(payload_bytes)
                tmp_path = tmp.name

            result = client.add(tmp_path, pin=True)
            cid = result["Hash"]
            logger.info("Uploaded payload to IPFS: CID=%s  SHA256=%s", cid, sha256_hash)
            Path(tmp_path).unlink(missing_ok=True)
            return cid, sha256_hash

    except Exception as exc:  # noqa: BLE001
        logger.error("IPFS upload failed (%s) — using hash-only fallback", exc)
        return f"sha256:{sha256_hash}", sha256_hash


def verify_ipfs_payload(cid: str, expected_hash: str) -> bool:
    """
    Download a payload from IPFS by *cid* and verify its SHA-256 matches *expected_hash*.
    Returns True if the payload is intact, False otherwise.
    """
    if cid.startswith("sha256:"):
        # Hash-only fallback mode — nothing to fetch
        return cid == f"sha256:{expected_hash}"

    if ipfshttpclient is None:
        logger.error("ipfshttpclient not installed — cannot verify IPFS payload")
        return False

    try:
        with ipfshttpclient.connect(IPFS_API_URL) as client:
            payload_bytes = client.cat(cid)
            actual_hash = compute_sha256(payload_bytes)
            match = actual_hash == expected_hash
            if match:
                logger.info("IPFS verification PASSED for CID=%s", cid)
            else:
                logger.error(
                    "IPFS verification FAILED for CID=%s  expected=%s  got=%s",
                    cid, expected_hash, actual_hash,
                )
            return match
    except Exception as exc:  # noqa: BLE001
        logger.error("IPFS fetch failed for CID=%s: %s", cid, exc)
        return False


if __name__ == "__main__":
    # Quick smoke test
    sample = {
        "event_id": "evt_test_001",
        "raw_features": {"src_ip": "10.0.0.5", "dst_port": 22, "pkt_count": 412},
        "attack_category": "PortScan",
        "detection_confidence": 0.97,
    }
    cid, h = upload_to_ipfs(sample)
    print(f"CID  : {cid}")
    print(f"SHA256: {h}")
    print(f"Verify: {verify_ipfs_payload(cid, h)}")
