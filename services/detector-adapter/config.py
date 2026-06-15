"""Detector Adapter configuration — reads from environment variables with safe defaults."""
import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class Config:
    # API
    api_host: str = field(default_factory=lambda: os.getenv("API_HOST", "0.0.0.0"))
    api_port: int = field(default_factory=lambda: int(os.getenv("API_PORT", "8000")))
    api_workers: int = field(default_factory=lambda: int(os.getenv("API_WORKERS", "1")))
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    # Kafka — default to localhost so the service starts even when Kafka is absent
    kafka_bootstrap: str = field(default_factory=lambda: os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"))
    kafka_topic: str = field(default_factory=lambda: os.getenv("KAFKA_TOPIC", "security-events"))
    kafka_dlq_topic: str = field(default_factory=lambda: os.getenv("KAFKA_DLQ_TOPIC", "security-events-dlq"))
    kafka_connect_timeout: int = field(default_factory=lambda: int(os.getenv("KAFKA_CONNECT_TIMEOUT", "5")))

    # Optional — producer will skip Kafka gracefully if unavailable
    kafka_optional: bool = field(default_factory=lambda: os.getenv("KAFKA_OPTIONAL", "true").lower() == "true")


config = Config()
