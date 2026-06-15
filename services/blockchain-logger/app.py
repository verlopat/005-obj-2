"""
services/blockchain-logger/app.py

Kafka → IPFS → Hyperledger Fabric → Redis pipeline.

Pipeline per message:
  1. Validate event against shared SecurityEvent schema.
  2. Pin canonical payload to IPFS — get real CID.
  3. Compute SHA-256 over canonical payload bytes.
  4. Sign (canonical_bytes) with ECDSA P-256 agent key.
  5. Submit chaincode Invoke (LogEvent) via Fabric Gateway gRPC.
  6. Write committed record to Redis (shared with audit-api).
  7. Commit Kafka offset ONLY after all steps succeed.
  8. On any failure: bounded retries with exponential backoff,
     then DLQ — never silent-drop.

No mock paths.  If a required env var is missing the process exits at startup.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
import traceback
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────
# Bootstrap: make shared/ importable regardless of cwd
# ─────────────────────────────────────────────────────────────────────────
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import redis  # type: ignore
from confluent_kafka import Consumer, KafkaError, Producer  # type: ignore
from cryptography.hazmat.primitives import hashes, serialization  # type: ignore
from cryptography.hazmat.primitives.asymmetric import ec  # type: ignore
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # type: ignore
from cryptography.hazmat.backends import default_backend  # type: ignore

from shared import config as cfg
from shared.event_schema import SecurityEvent
from shared.ipfs_client import IPFSError, add_and_pin, fetch_and_verify

# ── Logging ──────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [logger] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("blockchain-logger")

# ── Fabric Gateway helpers ────────────────────────────────────────────────────────
def _build_fabric_gateway():
    """
    Build and return a Fabric Gateway Network object using the official
    fabric-gateway Python SDK (pip install fabric-sdk-py or hfc).

    We use the lower-level grpc-based gateway from fabric-protos-python +
    fabric-sdk-py 1.x which exposes a Gateway class.
    """
    import grpc  # type: ignore
    from fabric_sdk_py.fabric_network.gateway import Gateway  # type: ignore
    from fabric_sdk_py.fabric_network.network import Network  # type: ignore

    # Load TLS credentials
    with open(cfg.FABRIC_TLS_CERT, "rb") as f:
        tls_root_cert = f.read()

    credentials = grpc.ssl_channel_credentials(root_certificates=tls_root_cert)
    channel = grpc.secure_channel(cfg.FABRIC_PEER_ENDPOINT, credentials)

    # Load signing identity
    with open(cfg.FABRIC_SIGN_CERT, "rb") as f:
        sign_cert_pem = f.read()
    with open(cfg.FABRIC_SIGN_KEY, "rb") as f:
        sign_key_pem = f.read()

    gateway = Gateway()
    gateway.connect(
        channel,
        {
            "wallet": None,
            "identity": cfg.FABRIC_MSP_ID,
            "clientTlsCert": sign_cert_pem,
        },
    )
    network: Network = gateway.get_network(cfg.FABRIC_CHANNEL)
    contract = network.get_contract(cfg.FABRIC_CHAINCODE)
    return gateway, contract


_gateway = None
_contract = None


def _get_contract():
    global _gateway, _contract
    if _contract is None:
        _gateway, _contract = _build_fabric_gateway()
    return _contract


def _submit_to_fabric(event: SecurityEvent) -> str:
    """
    Submit a LogEvent transaction and return the tx_id string.
    Raises RuntimeError if the submission fails.
    """
    contract = _get_contract()
    payload = json.dumps(event.to_ledger_dict(), default=str)
    # submit_transaction blocks until the peer has committed the block
    tx_id = contract.submit_transaction(
        "LogEvent",
        payload,
    )
    return tx_id.decode() if isinstance(tx_id, bytes) else str(tx_id)


# ── ECDSA signing ───────────────────────────────────────────────────────────────────
_agent_private_key: Optional[ec.EllipticCurvePrivateKey] = None
_agent_identity: Optional[str] = None


def _load_agent_key():
    global _agent_private_key, _agent_identity
    if _agent_private_key is not None:
        return
    with open(cfg.AGENT_KEY_PATH, "rb") as f:
        _agent_private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
    with open(cfg.AGENT_CERT_PATH, "rb") as f:
        cert_pem = f.read()
    # Use the PEM cert bytes as the identity string (hex fingerprint could also work)
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    _agent_identity = cert.subject.rfc4514_string()


def _sign(data: bytes) -> str:
    _load_agent_key()
    sig = _agent_private_key.sign(data, ec.ECDSA(hashes.SHA256()))  # type: ignore
    return sig.hex()


# ── Redis helpers ───────────────────────────────────────────────────────────────────
_redis: Optional[redis.Redis] = None


def _get_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.from_url(cfg.REDIS_URL, decode_responses=True)
    return _redis


def _write_to_redis(event: SecurityEvent) -> None:
    r = _get_redis()
    event_id = str(event.event_id)
    key = cfg.REDIS_KEY_PREFIX + event_id
    record = json.dumps(event.to_ledger_dict(), default=str)

    pipe = r.pipeline()
    pipe.set(key, record, ex=cfg.REDIS_TTL_S)
    # Asset index: sorted set keyed by asset_id, scored by timestamp
    ts = event.timestamp.timestamp()
    pipe.zadd(cfg.REDIS_IDX_ASSET + event.asset_id, {event_id: ts})
    # Severity index
    pipe.zadd(cfg.REDIS_IDX_SEV + event.severity.value, {event_id: ts})
    pipe.execute()
    log.info("Redis write OK  event_id=%s", event_id)


# ── DLQ producer ────────────────────────────────────────────────────────────────────
_dlq_producer: Optional[Producer] = None


def _get_dlq_producer() -> Producer:
    global _dlq_producer
    if _dlq_producer is None:
        _dlq_producer = Producer(
            {"bootstrap.servers": cfg.KAFKA_BOOTSTRAP_SERVERS}
        )
    return _dlq_producer


def _send_to_dlq(raw: bytes, reason: str) -> None:
    prod = _get_dlq_producer()
    dlq_msg = json.dumps({"reason": reason, "original": raw.decode("utf-8", errors="replace")})
    prod.produce(cfg.KAFKA_TOPIC_DLQ, value=dlq_msg.encode())
    prod.flush()
    log.error("DLQ: sent message  reason=%s", reason)


# ── Core pipeline ───────────────────────────────────────────────────────────────────

def process_message(raw: bytes) -> None:
    """
    Full pipeline for one Kafka message.  Raises on unrecoverable error
    so the caller can route to DLQ.  Transient errors are retried.
    """
    # Step 1 — parse & validate schema
    try:
        event = SecurityEvent.from_kafka_bytes(raw)
    except Exception as exc:
        raise ValueError(f"Schema validation failed: {exc}") from exc

    log.info("Processing event_id=%s asset=%s severity=%s",
             event.event_id, event.asset_id, event.severity.value)

    # Step 2 — build canonical payload bytes
    payload_bytes = event.canonical_bytes()

    # Step 3 — add + pin to IPFS, get real CID
    cid, sha256_hex = add_and_pin(payload_bytes)
    event.ipfs_cid = cid
    event.sha256 = sha256_hex

    # Step 4 — verify IPFS round-trip before writing to chain
    if not fetch_and_verify(cid, sha256_hex):
        raise IPFSError(f"IPFS round-trip verify failed for CID {cid}")

    # Step 5 — sign canonical payload with agent key
    _load_agent_key()
    event.agent_identity = _agent_identity
    event.agent_signature = _sign(payload_bytes)

    # Step 6 — submit to Fabric (blocks until block committed)
    tx_id = _submit_to_fabric(event)
    event.tx_id = tx_id
    log.info("Fabric commit OK  tx_id=%s  event_id=%s", tx_id, event.event_id)

    # Step 7 — write committed record to Redis (shared cache for audit-api)
    _write_to_redis(event)

    # Step 8 — offset is committed by the caller after this returns without error


# ── Main consumer loop ─────────────────────────────────────────────────────────────────

def main() -> None:
    log.info("blockchain-logger starting  config=%s", cfg.dump())

    consumer = Consumer(
        {
            "bootstrap.servers":  cfg.KAFKA_BOOTSTRAP_SERVERS,
            "group.id":           cfg.KAFKA_CONSUMER_GROUP,
            "auto.offset.reset":  "earliest",
            # Manual commit — we call consumer.commit() only after success
            "enable.auto.commit": "false",
        }
    )
    consumer.subscribe([cfg.KAFKA_TOPIC_EVENTS])
    log.info("Subscribed to topic %s", cfg.KAFKA_TOPIC_EVENTS)

    _running = True

    def _stop(sig, frame):  # type: ignore
        nonlocal _running
        log.info("Signal %s received — shutting down", sig)
        _running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    max_retries = cfg.FABRIC_MAX_RETRIES
    backoff_base = cfg.FABRIC_RETRY_BACKOFF_S

    while _running:
        msg = consumer.poll(timeout=1.0)
        if msg is None:
            continue
        if msg.error():
            if msg.error().code() == KafkaError._PARTITION_EOF:
                continue
            log.error("Kafka consumer error: %s", msg.error())
            continue

        raw: bytes = msg.value()
        succeeded = False

        for attempt in range(1, max_retries + 1):
            try:
                process_message(raw)
                succeeded = True
                break
            except ValueError as exc:
                # Unrecoverable: schema/parse error — go straight to DLQ
                log.error("Unrecoverable error (attempt %d): %s", attempt, exc)
                _send_to_dlq(raw, str(exc))
                succeeded = True  # mark as handled (no offset stall)
                break
            except Exception as exc:
                log.warning(
                    "Transient error (attempt %d/%d): %s",
                    attempt, max_retries, exc,
                )
                traceback.print_exc()
                if attempt < max_retries:
                    sleep_s = backoff_base * (2 ** (attempt - 1))
                    log.info("Retrying in %.1f s ...", sleep_s)
                    time.sleep(sleep_s)
                else:
                    log.error(
                        "All %d retries exhausted — sending to DLQ", max_retries
                    )
                    _send_to_dlq(raw, f"max retries exceeded: {exc}")
                    succeeded = True  # handled via DLQ

        if succeeded:
            # Commit offset only after successful processing or DLQ routing
            consumer.commit(message=msg, asynchronous=False)
            log.debug("Kafka offset committed  partition=%s offset=%s",
                      msg.partition(), msg.offset())

    consumer.close()
    log.info("blockchain-logger stopped")


if __name__ == "__main__":
    main()
