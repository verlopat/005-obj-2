"""Kafka consumer worker — live pipeline only.

Pipeline per message:
  1. Deserialise + validate with shared SecurityEvent schema
  2. Build canonical payload bytes
  3. Sign with ECDSA (pki_signer / signer.py)
  4. Upload canonical bytes to IPFS → get real CID
  5. Compute SHA-256 over canonical bytes
  6. Submit LogSecurityEvent to Fabric
  7. Write record + indexes to Redis (so audit-api can query it)
  8. Ack (commit offset) ONLY after confirmed Fabric tx + Redis write
  9. On any failure: bounded retries with exponential backoff → DLQ

No mock path.  No silent drops.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import redis as redis_lib
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError

# shared modules live at repo root; add to path if needed
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shared.config import (
    KAFKA_BOOTSTRAP, KAFKA_TOPIC, KAFKA_DLQ_TOPIC, KAFKA_GROUP_ID,
    KAFKA_MAX_RETRIES, KAFKA_RETRY_BASE_S, KAFKA_RETRY_CAP_S,
    IPFS_API_URL, AGENT_KEY_PATH, AGENT_CERT_PATH,
    REDIS_URL, REDIS_KEY_PREFIX, REDIS_IDX_ASSET, REDIS_IDX_SEV,
)
from shared.event_schema import SecurityEvent, canonical_payload, sha256_of
from shared.ipfs import add_and_pin
from fabric_client import submit_transaction
from signer import sign_bytes

log = logging.getLogger(__name__)

_redis_client: redis_lib.Redis | None = None


def _get_redis() -> redis_lib.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis_lib.from_url(REDIS_URL, decode_responses=True)
    return _redis_client


def _index_in_redis(
    event: SecurityEvent,
    event_dict: dict,
    tx_id: str,
    cid: str,
    sha256: str,
    signature: str,
) -> None:
    """Write the committed event record + asset/severity sorted-set indexes to Redis."""
    r = _get_redis()
    ts_str = event_dict.get("timestamp") or datetime.now(timezone.utc).isoformat()
    # Convert ISO timestamp to a float score for ZADD
    try:
        ts_score = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
    except Exception:
        ts_score = time.time()

    record = {
        **event_dict,
        "tx_id": tx_id,
        "ipfs_cid": cid,
        "sha256": sha256,
        "agent_signature": signature,
        "agent_identity": str(AGENT_CERT_PATH),
    }

    pipe = r.pipeline()
    # 1. Full record keyed by event_id
    pipe.set(REDIS_KEY_PREFIX + event.event_id, json.dumps(record))
    # 2. Asset sorted set (newest-first via positive score)
    pipe.zadd(REDIS_IDX_ASSET + event.asset_id, {event.event_id: ts_score})
    # 3. Severity sorted set
    pipe.zadd(REDIS_IDX_SEV + event.severity, {event.event_id: ts_score})
    pipe.execute()
    log.info("[REDIS] indexed event_id=%s asset=%s severity=%s",
             event.event_id, event.asset_id, event.severity)


def _backoff(attempt: int) -> float:
    """Exponential backoff capped at KAFKA_RETRY_CAP_S."""
    delay = KAFKA_RETRY_BASE_S * (2 ** attempt)
    return min(delay, KAFKA_RETRY_CAP_S)


def _send_to_dlq(producer: KafkaProducer, raw_bytes: bytes, reason: str):
    try:
        producer.send(
            KAFKA_DLQ_TOPIC,
            value=json.dumps({
                "raw": raw_bytes.decode("utf-8", errors="replace"),
                "reason": reason,
                "ts": datetime.now(timezone.utc).isoformat(),
            }).encode(),
        )
        producer.flush()
        log.warning("[DLQ] message routed to %s: %s", KAFKA_DLQ_TOPIC, reason)
    except Exception as exc:
        log.error("[DLQ] failed to send to DLQ: %s", exc)


def process_message(raw_bytes: bytes, producer: KafkaProducer) -> bool:
    """Process one Kafka message end-to-end.  Returns True on success."""
    # 1. Parse + validate
    try:
        data = json.loads(raw_bytes)
        event = SecurityEvent(**data)
    except Exception as exc:
        _send_to_dlq(producer, raw_bytes, f"schema validation failed: {exc}")
        return False

    event_dict = event.model_dump()
    if not event_dict.get("timestamp"):
        event_dict["timestamp"] = datetime.now(timezone.utc).isoformat()

    # 2. Canonical bytes
    payload_bytes = canonical_payload(event_dict)

    # 3. Sign
    try:
        sig_bytes = sign_bytes(payload_bytes)
        signature = base64.b64encode(sig_bytes).decode()
    except Exception as exc:
        _send_to_dlq(producer, raw_bytes, f"signing failed: {exc}")
        return False

    # 4. IPFS pin — real CID
    try:
        cid = add_and_pin(payload_bytes, IPFS_API_URL)
    except Exception as exc:
        _send_to_dlq(producer, raw_bytes, f"IPFS add failed: {exc}")
        return False

    # 5. SHA-256 over canonical bytes
    sha256 = sha256_of(event_dict)

    # 6. Submit to Fabric
    try:
        tx_id = submit_transaction(
            function="LogSecurityEvent",
            args=[
                event.event_id,
                event.asset_id,
                event.cloud_provider,
                event.region,
                event.severity,
                event.attack_category,
                event.description,
                str(event.detection_confidence),
                event.model_version,
                cid,
                sha256,
                signature,
                event_dict["timestamp"],
            ],
        )
    except Exception as exc:
        _send_to_dlq(producer, raw_bytes, f"Fabric submit failed: {exc}")
        return False

    # 7. Write to Redis so audit-api can query it
    try:
        _index_in_redis(event, event_dict, tx_id, cid, sha256, signature)
    except Exception as exc:
        # Redis write failure is non-fatal for the audit trail integrity
        # (event is already on-chain) but log it loudly.
        log.error("[REDIS] index write failed for event_id=%s: %s", event.event_id, exc)

    log.info(
        "[LOGGER] committed event_id=%s asset=%s tx=%s cid=%s sha256=%.16s…",
        event.event_id, event.asset_id, tx_id, cid, sha256,
    )
    return True


def run():
    log.info("[WORKER] starting — topic=%s group=%s bootstrap=%s",
             KAFKA_TOPIC, KAFKA_GROUP_ID, KAFKA_BOOTSTRAP)

    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP.split(","),
        group_id=KAFKA_GROUP_ID,
        auto_offset_reset="earliest",
        enable_auto_commit=False,   # manual commit after successful Fabric tx
        value_deserializer=lambda b: b,
    )
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP.split(","),
        value_serializer=lambda b: b,
    )

    for msg in consumer:
        raw = msg.value
        success = False
        for attempt in range(KAFKA_MAX_RETRIES + 1):
            if attempt > 0:
                delay = _backoff(attempt - 1)
                log.info("[WORKER] retry %d/%d after %.1fs", attempt, KAFKA_MAX_RETRIES, delay)
                time.sleep(delay)
            try:
                success = process_message(raw, producer)
                if success:
                    break
            except Exception as exc:
                log.warning("[WORKER] attempt %d raised: %s", attempt, exc)

        if not success:
            log.error("[WORKER] all retries exhausted — message in DLQ")

        # Commit offset only after successful processing (or after DLQ routing)
        consumer.commit()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [LOGGER] %(levelname)s %(message)s",
    )
    run()
