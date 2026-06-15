"""Configuration for the blockchain-logger service."""
import os
from dataclasses import dataclass


@dataclass
class Config:
    kafka_bootstrap_servers: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    kafka_topic_events: str = os.getenv("KAFKA_TOPIC_EVENTS", "security-events")
    kafka_consumer_group: str = os.getenv("KAFKA_CONSUMER_GROUP", "blockchain-logger-group")
    kafka_auto_offset_reset: str = os.getenv("KAFKA_AUTO_OFFSET_RESET", "earliest")
    kafka_max_poll_records: int = int(os.getenv("KAFKA_MAX_POLL_RECORDS", "50"))
    kafka_poll_timeout_seconds: float = float(os.getenv("KAFKA_POLL_TIMEOUT_SECONDS", "1.0"))
    fabric_gateway_host: str = os.getenv("FABRIC_GATEWAY_HOST", "localhost")
    fabric_gateway_port: int = int(os.getenv("FABRIC_GATEWAY_PORT", "7051"))
    fabric_tls_cert_path: str = os.getenv("FABRIC_TLS_CERT_PATH", "/certs/tls/ca.crt")
    fabric_msp_id: str = os.getenv("FABRIC_MSP_ID", "Org1MSP")
    fabric_cert_path: str = os.getenv("FABRIC_CERT_PATH", "/certs/signcerts/cert.pem")
    fabric_key_path: str = os.getenv("FABRIC_KEY_PATH", "/certs/keystore/key.pem")
    fabric_channel_name: str = os.getenv("FABRIC_CHANNEL_NAME", "security-channel")
    fabric_chaincode_name: str = os.getenv("FABRIC_CHAINCODE_NAME", "security_logger")
    fabric_submit_timeout_seconds: int = int(os.getenv("FABRIC_SUBMIT_TIMEOUT_SECONDS", "30"))
    ipfs_api_url: str = os.getenv("IPFS_API_URL", "http://localhost:5001")
    ipfs_gateway_url: str = os.getenv("IPFS_GATEWAY_URL", "http://localhost:8080")
    ipfs_timeout_seconds: int = int(os.getenv("IPFS_TIMEOUT_SECONDS", "15"))
    max_retries: int = int(os.getenv("MAX_RETRIES", "5"))
    retry_base_delay_seconds: float = float(os.getenv("RETRY_BASE_DELAY_SECONDS", "1.0"))
    retry_max_delay_seconds: float = float(os.getenv("RETRY_MAX_DELAY_SECONDS", "60.0"))
    signing_key_path: str = os.getenv("SIGNING_KEY_PATH", "/certs/signing/private_key.pem")
    signing_cert_path: str = os.getenv("SIGNING_CERT_PATH", "/certs/signing/cert.pem")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    metrics_port: int = int(os.getenv("METRICS_PORT", "9091"))
    worker_threads: int = int(os.getenv("WORKER_THREADS", "4"))


config = Config()
