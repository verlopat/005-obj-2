"""Kafka producer with idempotency, retries, and DLQ fallback."""
import json
import logging
import threading
from typing import Callable, Optional
from confluent_kafka import Producer, KafkaException
from config import config

logger = logging.getLogger(__name__)

class SecurityEventProducer:
    def __init__(self):
        self._producer: Optional[Producer] = None
        self._lock = threading.Lock()
        self._healthy = False

    def _get_producer(self) -> Producer:
        if self._producer is None:
            with self._lock:
                if self._producer is None:
                    conf = {
                        "bootstrap.servers": config.kafka_bootstrap_servers,
                        "acks": config.kafka_producer_acks,
                        "retries": config.kafka_producer_retries,
                        "linger.ms": config.kafka_producer_linger_ms,
                        "compression.type": config.kafka_producer_compression,
                        "enable.idempotence": True,
                        "max.in.flight.requests.per.connection": 5,
                        "delivery.timeout.ms": 30000,
                    }
                    self._producer = Producer(conf)
                    self._healthy = True
                    logger.info("Kafka producer initialized")
        return self._producer

    def _delivery_callback(self, err, msg):
        if err:
            logger.error("Delivery failed for event %s: %s", msg.key(), err)
        else:
            logger.debug("Event %s delivered to %s [%d] offset %d",
                         msg.key(), msg.topic(), msg.partition(), msg.offset())

    def produce(self, event_id: str, payload: dict, on_delivery: Optional[Callable] = None) -> None:
        producer = self._get_producer()
        value = json.dumps(payload, default=str).encode("utf-8")
        producer.produce(
            topic=config.kafka_topic_events,
            key=event_id.encode("utf-8"),
            value=value,
            on_delivery=on_delivery or self._delivery_callback,
        )
        producer.poll(0)

    def produce_dlq(self, event_id: str, payload: dict, reason: str) -> None:
        producer = self._get_producer()
        payload["_dlq_reason"] = reason
        value = json.dumps(payload, default=str).encode("utf-8")
        producer.produce(
            topic=config.kafka_topic_dlq,
            key=event_id.encode("utf-8"),
            value=value,
            on_delivery=self._delivery_callback,
        )
        producer.poll(0)

    def flush(self, timeout: float = 10.0) -> int:
        return self._get_producer().flush(timeout)

    def is_healthy(self) -> bool:
        try:
            self._get_producer()
            return self._healthy
        except KafkaException:
            return False

    def close(self):
        if self._producer:
            self._producer.flush(30)
            self._producer = None
            self._healthy = False

producer = SecurityEventProducer()
