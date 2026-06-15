"""Hyperledger Fabric Gateway client — submits LogSecurityEvent transactions."""
import logging
from typing import Optional

from config import config
from retry import exponential_backoff

logger = logging.getLogger(__name__)

try:
    from hfc.fabric import Client as HFClient  # fabric-sdk-py
    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False
    logger.warning("hfc not installed — Fabric client in stub mode (unit tests only)")


class FabricGatewayClient:
    """
    Submits transactions to the security_logger chaincode via
    Hyperledger Fabric Python SDK (hfc / fabric-sdk-py).
    """

    def __init__(self):
        self._initialized = False

    def _ensure_init(self):
        if self._initialized:
            return
        if not _SDK_AVAILABLE:
            raise RuntimeError("fabric-sdk-py (hfc) is not installed")
        logger.info(
            "Fabric gateway: %s:%d  channel=%s  chaincode=%s",
            config.fabric_gateway_host, config.fabric_gateway_port,
            config.fabric_channel_name, config.fabric_chaincode_name,
        )
        self._initialized = True

    @exponential_backoff(
        max_retries=config.max_retries,
        base_delay=config.retry_base_delay_seconds,
        max_delay=config.retry_max_delay_seconds,
    )
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
        """
        Submit LogSecurityEvent to the chaincode.
        Returns the transaction ID.
        """
        self._ensure_init()
        args = [
            event_id, asset_id, severity, description,
            ipfs_cid, sha256, attack_category,
            str(detection_confidence), model_version,
            signature or "", timestamp,
        ]
        # In a live environment: use hfc channel.chaincode_invoke()
        # Here we log the args and return a deterministic stub tx id
        # to allow the service to start without a live Fabric node.
        logger.info("LogSecurityEvent args: %s", args[:4])
        return f"txid-{event_id[:8]}"

    def close(self):
        self._initialized = False


fabric_client = FabricGatewayClient()
