"""Audit API configuration — reads from environment variables with safe defaults."""
import os
from dataclasses import dataclass, field


@dataclass
class Config:
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    api_host: str = field(default_factory=lambda: os.getenv("API_HOST", "0.0.0.0"))
    api_port: int = field(default_factory=lambda: int(os.getenv("API_PORT", "8001")))

    # Fabric
    fabric_peer_endpoint: str = field(default_factory=lambda: os.getenv("FABRIC_PEER_ENDPOINT", "localhost:7051"))
    fabric_channel: str = field(default_factory=lambda: os.getenv("FABRIC_CHANNEL", "security-channel"))
    fabric_chaincode: str = field(default_factory=lambda: os.getenv("FABRIC_CHAINCODE", "security_logger"))
    fabric_msp_id: str = field(default_factory=lambda: os.getenv("FABRIC_MSP_ID", "Org1MSP"))
    fabric_tls_cert: str = field(default_factory=lambda: os.getenv("FABRIC_TLS_CERT", ""))
    fabric_sign_cert: str = field(default_factory=lambda: os.getenv("FABRIC_SIGN_CERT", ""))
    fabric_sign_key: str = field(default_factory=lambda: os.getenv("FABRIC_SIGN_KEY", ""))
    fabric_optional: bool = field(default_factory=lambda: os.getenv("FABRIC_OPTIONAL", "true").lower() == "true")


config = Config()
