"""Configuration for the audit-api service."""
import os
from dataclasses import dataclass


@dataclass
class Config:
    fabric_gateway_host: str  = os.getenv("FABRIC_GATEWAY_HOST",  "localhost")
    fabric_gateway_port: int  = int(os.getenv("FABRIC_GATEWAY_PORT", "7051"))
    fabric_tls_cert_path: str = os.getenv("FABRIC_TLS_CERT_PATH",   "/certs/tls/ca.crt")
    fabric_msp_id: str        = os.getenv("FABRIC_MSP_ID",          "Org1MSP")
    fabric_cert_path: str     = os.getenv("FABRIC_CERT_PATH",       "/certs/signcerts/cert.pem")
    fabric_key_path: str      = os.getenv("FABRIC_KEY_PATH",        "/certs/keystore/key.pem")
    fabric_channel_name: str  = os.getenv("FABRIC_CHANNEL_NAME",    "security-channel")
    fabric_chaincode_name: str= os.getenv("FABRIC_CHAINCODE_NAME",  "security_logger")
    api_host: str             = os.getenv("API_HOST",    "0.0.0.0")
    api_port: int             = int(os.getenv("API_PORT",  "8001"))
    api_workers: int          = int(os.getenv("API_WORKERS", "2"))
    log_level: str            = os.getenv("LOG_LEVEL",   "INFO")
    metrics_port: int         = int(os.getenv("METRICS_PORT", "9092"))
    report_output_dir: str    = os.getenv("REPORT_OUTPUT_DIR", "/reports")


config = Config()
