"""Configuration for the detector-adapter service."""
import os
from dataclasses import dataclass

@dataclass
class Config:
    kafka_bootstrap_servers: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    kafka_topic_events: str = os.getenv("KAFKA_TOPIC_EVENTS", "security-events")
    kafka_topic_dlq: str = os.getenv("KAFKA_TOPIC_DLQ", "security-events-dlq")
    kafka_producer_acks: str = os.getenv("KAFKA_PRODUCER_ACKS", "all")
    kafka_producer_retries: int = int(os.getenv("KAFKA_PRODUCER_RETRIES", "5"))
    kafka_producer_linger_ms: int = int(os.getenv("KAFKA_PRODUCER_LINGER_MS", "5"))
    kafka_producer_compression: str = os.getenv("KAFKA_PRODUCER_COMPRESSION", "gzip")
    api_host: str = os.getenv("API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("API_PORT", "8000"))
    api_workers: int = int(os.getenv("API_WORKERS", "4"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    metrics_port: int = int(os.getenv("METRICS_PORT", "9090"))

config = Config()
