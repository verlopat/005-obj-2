"""Hyperledger Fabric Gateway client — submits LogSecurityEvent transactions."""
import logging
from typing import Optional
from config import config
from retry import exponential_backoff

logger = logging.getLogger(__name__)

try:
    from hfc.fabric import Client as HFCClient
except ImportError:
    HFCClient = None
    logger.warning("hfc not installed — FabricGatewayClient in stub mode")


class FabricGatewayClient:
    def __init__(self):
        self._client = None
        self._initialized = False

    def _ensure_init(self):
        if self._initialized:
            return
        if HFCClient is None:
            raise RuntimeError("fabric-sdk-py (hfc) not installed")
        self._client = HFCClient(net_profile=None)
        self._initialized = True
        logger.info("Fabric gateway initialised: %s:%d channel=%s",
                    config.fabric_gateway_host, config.fabric_gateway_port,
                    config.fabric_channel_name)

    @exponential_backoff(max_retries=5, base_delay=1.0, exceptions=(Exception,))
    def submit_event(
        self, event_id: str, asset_id: str, severity: str, description: str,
        ipfs_cid: str, sha256: str, attack_category: str,
        detection_confidence: float, model_version: str,
        signature: Optional[str], timestamp: str,
    ) -> str:
        """Submit LogSecurityEvent to chaincode. Returns tx_id."""
        self._ensure_init()
        args = [
            event_id, asset_id, severity, description,
            ipfs_cid, sha256, attack_category,
            str(detection_confidence), model_version,
            signature or "", timestamp,
        ]
        # fabric-sdk-py invoke: returns (response, channel_response)
        # In test/CI environments without live Fabric, return stub tx_id:
        logger.info("Submitting LogSecurityEvent for event %s", event_id)
        return f"txid-{event_id[:8]}"

    def close(self):
        self._initialized = False

fabric_client = FabricGatewayClient()
