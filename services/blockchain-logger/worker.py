"""Kafka consumer worker — polls events and logs them to Fabric + IPFS."""
import json
import logging
import threading
import time
from datetime import datetime
from typing import Optional
from confluent_kafka import Consumer, KafkaError
from prometheus_client import Counter, Histogram, Gauge
from config import config
from fabric_client import fabric_client
from ipfs_client import ipfs_client
from schemas import LogResult, SecurityEventMessage
from signer import signer

logger = logging.getLogger(__name__)
EVENTS_LOGGED = Counter("logger_events_logged_total", "Events logged to blockchain", ["severity"])
EVENTS_FAILED = Counter("logger_events_failed_total", "Events that failed to log", ["reason"])
LOG_LATENCY   = Histogram("logger_event_log_latency_seconds", "Kafka-to-chain latency",
                           buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0])

class BlockchainLoggerWorker:
    def __init__(self):
        self._running = False
        self._threads = []

    def _make_consumer(self) -> Consumer:
        return Consumer({
            "bootstrap.servers": config.kafka_bootstrap_servers,
            "group.id": config.kafka_consumer_group,
            "auto.offset.reset": config.kafka_auto_offset_reset,
            "enable.auto.commit": False,
            "max.poll.interval.ms": 300000,
            "session.timeout.ms": 30000,
        })

    def _process_message(self, raw_value: bytes) -> Optional[LogResult]:
        start = time.perf_counter()
        try:
            payload = json.loads(raw_value)
            event = SecurityEventMessage(**payload)
        except Exception as exc:
            EVENTS_FAILED.labels(reason="deserialize").inc()
            logger.error("Failed to deserialize message: %s", exc)
            return None

        try:
            cid, sha256 = ipfs_client.upload(payload)
        except Exception as exc:
            EVENTS_FAILED.labels(reason="ipfs").inc()
            logger.error("IPFS upload failed for event %s: %s", event.event_id, exc)
            raise

        signature = signer.sign(payload) if signer.enabled else None

        try:
            tx_id = fabric_client.submit_event(
                event_id=event.event_id, asset_id=event.asset_id,
                severity=event.severity, description=event.description,
                ipfs_cid=cid, sha256=sha256,
                attack_category=event.attack_category,
                detection_confidence=event.detection_confidence,
                model_version=event.model_version,
                signature=signature, timestamp=event.timestamp,
            )
        except Exception as exc:
            EVENTS_FAILED.labels(reason="fabric").inc()
            logger.error("Fabric submission failed for event %s: %s", event.event_id, exc)
            raise

        duration_ms = (time.perf_counter() - start) * 1000
        LOG_LATENCY.observe(duration_ms / 1000)
        EVENTS_LOGGED.labels(severity=event.severity).inc()
        result = LogResult(event_id=event.event_id, ipfs_cid=cid, sha256=sha256,
                           tx_id=tx_id, logged_at=datetime.utcnow(), duration_ms=duration_ms)
        logger.info("Logged event %s: tx=%s cid=%s %.1fms",
                    event.event_id, tx_id, cid, duration_ms)
        return result

    def _run_worker(self, worker_id: int):
        consumer = self._make_consumer()
        consumer.subscribe([config.kafka_topic_events])
        logger.info("Worker %d started, subscribed to %s", worker_id, config.kafka_topic_events)
        try:
            while self._running:
                msg = consumer.poll(config.kafka_poll_timeout_seconds)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    logger.error("Consumer error: %s", msg.error())
                    continue
                try:
                    self._process_message(msg.value())
                    consumer.commit(asynchronous=False)
                except Exception as exc:
                    logger.error("Worker %d error on message: %s", worker_id, exc)
        finally:
            consumer.close()
            logger.info("Worker %d stopped", worker_id)

    def start(self):
        self._running = True
        for i in range(config.worker_threads):
            t = threading.Thread(target=self._run_worker, args=(i,),
                                 daemon=True, name=f"logger-worker-{i}")
            t.start()
            self._threads.append(t)
        logger.info("Started %d logger workers", config.worker_threads)

    def stop(self):
        self._running = False
        for t in self._threads:
            t.join(timeout=15)
        self._threads.clear()

worker = BlockchainLoggerWorker()
