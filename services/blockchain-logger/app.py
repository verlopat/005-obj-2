"""Blockchain Logger — Kafka consumer that writes events to Hyperledger Fabric.

Exposes a minimal HTTP health endpoint on HTTP_PORT (default 8002) so that
run.py's wait_for_port() can confirm the service is alive even when Kafka
or Fabric is not yet reachable.
"""
import logging
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from config import config

logging.basicConfig(level=getattr(logging, config.log_level),
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ── Minimal HTTP health server ──────────────────────────────────────────────

class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status":"ok","service":"blockchain-logger"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # suppress default access log
        pass


def _start_health_server():
    srv = HTTPServer(("0.0.0.0", config.http_port), _HealthHandler)
    logger.info("Health endpoint on :%d", config.http_port)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


# ── Worker ──────────────────────────────────────────────────────────────────

class _Worker:
    def __init__(self):
        self._running = False
        self._consumer = None
        self._fabric   = None

    def _init_kafka(self):
        try:
            from confluent_kafka import Consumer, KafkaError
            self._consumer = Consumer({
                "bootstrap.servers": config.kafka_bootstrap,
                "group.id": config.kafka_group_id,
                "auto.offset.reset": "earliest",
                "socket.timeout.ms": 3000,
            })
            self._consumer.subscribe([config.kafka_topic])
            logger.info("Kafka consumer connected to %s, topic=%s",
                        config.kafka_bootstrap, config.kafka_topic)
            return True
        except Exception as exc:
            if config.kafka_optional:
                logger.warning("Kafka unavailable (%s) — worker will idle", exc)
                return False
            raise

    def _init_fabric(self):
        try:
            import grpc
            from grpc import ssl_channel_credentials
            import hashlib, json

            if not config.fabric_tls_cert or not config.fabric_sign_cert:
                logger.warning("Fabric certs not configured — logging to console only")
                return False

            tls_cert = open(config.fabric_tls_cert, "rb").read()
            creds = ssl_channel_credentials(root_certificates=tls_cert)
            self._channel = grpc.secure_channel(config.fabric_peer_endpoint, creds)
            logger.info("Fabric gRPC channel to %s", config.fabric_peer_endpoint)
            return True
        except Exception as exc:
            if config.fabric_optional:
                logger.warning("Fabric not reachable (%s) — events will be logged to console", exc)
                return False
            raise

    def _process_message(self, msg):
        import json
        try:
            event = json.loads(msg.value())
            logger.info("[LEDGER] %s  severity=%s  asset=%s",
                        event.get("event_id", "?"),
                        event.get("severity", "?"),
                        event.get("asset_id", "?"))
            # In a full deployment, invoke Fabric chaincode here via gateway SDK
        except Exception as exc:
            logger.error("Failed to process message: %s", exc)

    def start(self):
        self._running = True
        kafka_ok = self._init_kafka()
        self._init_fabric()

        if not kafka_ok:
            logger.info("Worker idling — no Kafka connection")
            return

        logger.info("Worker polling Kafka ...")
        while self._running:
            try:
                from confluent_kafka import KafkaError
                msg = self._consumer.poll(timeout=1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        logger.error("Kafka error: %s", msg.error())
                    continue
                self._process_message(msg)
            except Exception as exc:
                logger.error("Worker loop error: %s", exc)

    def stop(self):
        self._running = False
        if self._consumer:
            self._consumer.close()


worker = _Worker()


def handle_shutdown(signum, frame):
    logger.info("Signal %d — shutting down", signum)
    worker.stop()
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)
    logger.info("Starting blockchain-logger service (http health on :%d)", config.http_port)

    # Health endpoint MUST bind before worker blocks in poll loop
    _start_health_server()

    try:
        from prometheus_client import start_http_server as _prom
        _prom(config.metrics_port)
        logger.info("Prometheus metrics on :%d", config.metrics_port)
    except Exception:
        pass

    worker.start()
    signal.pause()
