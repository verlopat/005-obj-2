"""IPFS client — uploads event payloads and returns (CID, SHA-256)."""
import logging
from typing import Tuple

import requests

from config import config
from crypto_utils import canonical_json, sha256_digest
from retry import exponential_backoff

logger = logging.getLogger(__name__)


class IPFSClient:
    def __init__(self):
        self._session = requests.Session()

    @exponential_backoff(max_retries=3, base_delay=0.5)
    def upload(self, payload: dict) -> Tuple[str, str]:
        """Upload canonical JSON to IPFS. Returns (cid, sha256_hex)."""
        raw = canonical_json(payload)
        sha256 = sha256_digest(raw)
        response = self._session.post(
            f"{config.ipfs_api_url}/api/v0/add",
            files={"file": ("event.json", raw, "application/json")},
            params={"pin": "true", "cid-version": "1"},
            timeout=config.ipfs_timeout_seconds,
        )
        response.raise_for_status()
        cid = response.json()["Hash"]
        logger.info("IPFS upload: CID=%s SHA256=%s", cid, sha256)
        return cid, sha256

    def pin(self, cid: str) -> None:
        self._session.post(
            f"{config.ipfs_api_url}/api/v0/pin/add",
            params={"arg": cid},
            timeout=config.ipfs_timeout_seconds,
        ).raise_for_status()

    def close(self):
        self._session.close()


ipfs_client = IPFSClient()
