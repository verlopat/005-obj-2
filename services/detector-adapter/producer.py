"""Kafka producer with graceful degradation — runs in no-op mode when Kafka is unavailable."""
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class _NoOpProducer:
    """Stand-in producer when Kafka is unavailable. Events are logged but not forwarded."""
    _warned = False

    def produce(self, key: str, value: dict) -> None:
        if not self._warned:
            logger.warning("Kafka unavailable — running in no-op mode. Events will NOT be forwarded to blockchain-logger.")
            self._warned = True
        logger.debug("[no-op] event key=%s severity=%s", key, value.get("severity"))

    def produce_dlq(self, key: str, value: dict, error: str) -> None:
        logger.debug("[no-op dlq] key=%s error=%s", key, error)

    def flush(self, timeout: float = 5.0) -> None:
        pass

    def close(self) -> None:
        pass

    def is_healthy(self) -> bool:
        return False  # reports degraded, but service stays up


class _KafkaProducer:
    def __init__(self, bootstrap: str, topic: str, dlq_topic: str):
        from confluent_kafka import Producer as _P, KafkaException
        self._topic = topic
        self._dlq   = dlq_topic
        self._prod  = _P({"bootstrap.servers": bootstrap,
                          "socket.timeout.ms": 3000,
                          "message.timeout.ms": 5000})
        self._healthy = True
        logger.info("Kafka producer connected to %s", bootstrap)

    def produce(self, key: str, value: dict) -> None:
        self._prod.produce(
            self._topic,
            key=key.encode(),
            value=json.dumps(value, default=str).encode(),
        )
        self._prod.poll(0)

    def produce_dlq(self, key: str, value: dict, error: str) -> None:
        payload = {**value, "_error": error, "_dlq_ts": datetime.now(timezone.utc).isoformat()}
        self._prod.produce(self._dlq, key=key.encode(),
                           value=json.dumps(payload, default=str).encode())
        self._prod.poll(0)

    def flush(self, timeout: float = 5.0) -> None:
        self._prod.flush(timeout)

    def close(self) -> None:
        self.flush()

    def is_healthy(self) -> bool:
        return self._healthy


def _build_producer():
    """Try to build a real Kafka producer; fall back to no-op silently."""
    from config import config
    try:
        import confluent_kafka  # noqa: F401  — check import first
        return _KafkaProducer(config.kafka_bootstrap, config.kafka_topic, config.kafka_dlq_topic)
    except ImportError:
        logger.warning("confluent-kafka not installed — using no-op producer")
        return _NoOpProducer()
    except Exception as exc:
        if config.kafka_optional:
            logger.warning("Kafka not reachable (%s) — using no-op producer", exc)
            return _NoOpProducer()
        raise


producer = _build_producer()
