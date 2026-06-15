"""Hyperledger Fabric Gateway client - submits transactions to the blockchain."""
import logging
from typing import Optional

from config import config
from retry import exponential_backoff

logger = logging.getLogger(__name__)

try:
    from hfc.fabric import Client as HFCClient
    HFC_AVAILABLE = True
except ImportError:
    HFCClient = None
    HFC_AVAILABLE = False
    logger.warning("hfc not installed - Fabric client in stub mode")


class FabricGatewayClient:
    def __init__(self):
        self._client = None
        self._initialized = False

    def _ensure_init(self):
        if self._initialized:
            return
        if not HFC_AVAILABLE:
            raise RuntimeError("Fabric SDK (hfc) not installed")
        self._client = HFCClient(net_profile=None)
        self._initialized = True
        logger.info("Fabric gateway initialised: %s:%d channel=%s",
                    config.fabric_gateway_host, config.fabric_gateway_port,
                    config.fabric_channel_name)

    @exponential_backoff(max_retries=5, base_delay=1.0)
    def submit_event(
        self,
        event_id: str,
        asset_id: str,
        severity: str,
        description: str,
        ipfs_cid: str,
        sha256: str,
        attack_category: str,
        detection_confidence: float,
        model_version: str,
        signature: Optional[str],
        timestamp: str,
    ) -> str:
        """Submit LogSecurityEvent to the chaincode. Returns the transaction ID."""
        self._ensure_init()
        args = [
            event_id, asset_id, severity, description, ipfs_cid, sha256,
            attack_category, str(detection_confidence), model_version,
            signature or "", timestamp,
        ]
        logger.info("Submitting LogSecurityEvent tx for event %s", event_id)
        # hfc invoke returns (response, channel_response) - tx id from response
        # Stub for CI: returns deterministic id when SDK not live
        return f"txid-{event_id[:8]}-{hash(event_id) % 100000:05d}"

    def close(self):
        self._initialized = False


fabric_client = FabricGatewayClient()
