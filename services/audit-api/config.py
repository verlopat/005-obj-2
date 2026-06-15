"""Configuration for the audit-api service."""
import os
from dataclasses import dataclass

@dataclass
class Config:
    fabric_gateway_host: str = os.getenv("FABRIC_GATEWAY_HOST", "localhost")
    fabric_gateway_port: int = int(os.getenv("FABRIC_GATEWAY_PORT", "7051"))
    fabric_channel_name: str = os.getenv("FABRIC_CHANNEL_NAME", "security-channel")
    fabric_chaincode_name: str = os.getenv("FABRIC_CHAINCODE_NAME", "security_logger")
    fabric_msp_id: str = os.getenv("FABRIC_MSP_ID", "Org1MSP")
    fabric_cert_path: str = os.getenv("FABRIC_CERT_PATH", "/certs/signcerts/cert.pem")
    fabric_key_path: str = os.getenv("FABRIC_KEY_PATH", "/certs/keystore/key.pem")
    fabric_tls_cert_path: str = os.getenv("FABRIC_TLS_CERT_PATH", "/certs/tls/ca.crt")
    ipfs_gateway_url: str = os.getenv("IPFS_GATEWAY_URL", "http://localhost:8080")
    ipfs_api_url: str = os.getenv("IPFS_API_URL", "http://localhost:5001")
    reports_output_dir: str = os.getenv("REPORTS_OUTPUT_DIR", "/app/reports")
    api_host: str = os.getenv("API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("API_PORT", "8001"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    max_query_results: int = int(os.getenv("MAX_QUERY_RESULTS", "1000"))

config = Config()
