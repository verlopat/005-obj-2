"""
services/blockchain-logger/app.py

Kafka -> IPFS -> Hyperledger Fabric -> Redis pipeline.

Pipeline per message:
  1. Validate event against shared SecurityEvent schema.
  2. Pin canonical payload to IPFS -- get real CID.
  3. Compute SHA-256 over canonical payload bytes.
  4. Sign (canonical_bytes) with ECDSA P-256 agent key.
  5. Submit chaincode Invoke (LogEvent) via `peer chaincode invoke` CLI.
  6. Write committed record to Redis (shared with audit-api).
  7. Commit Kafka offset ONLY after all steps succeed.
  8. On any failure: bounded retries with exponential backoff,
     then DLQ -- never silent-drop.

Fabric transport: peer CLI subprocess (no SDK, Python-3.14-safe).
All cert/key paths are resolved to absolute paths anchored at REPO_ROOT
so relative values in .env work regardless of the process working dir.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Bootstrap: make shared/ importable regardless of cwd
# ---------------------------------------------------------------------------
# app.py lives at  <repo>/services/blockchain-logger/app.py
# so REPO_ROOT     = app.py -> parent -> parent -> parent
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import redis  # type: ignore
from confluent_kafka import Consumer, KafkaError, Producer  # type: ignore
from cryptography.hazmat.primitives import hashes, serialization  # type: ignore
from cryptography.hazmat.primitives.asymmetric import ec  # type: ignore
from cryptography.hazmat.backends import default_backend  # type: ignore

from shared import config as cfg
from shared.event_schema import SecurityEvent
from shared.ipfs_client import IPFSError, add_and_pin, fetch_and_verify

# -- Logging -----------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [logger] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("blockchain-logger")


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _abs(p: str) -> str:
    """
    Return an absolute path string.
    If p is already absolute, return it unchanged.
    If p is relative, resolve it against REPO_ROOT (the project root),
    NOT against the process cwd which varies depending on how the service
    was launched.
    """
    path = Path(p)
    if path.is_absolute():
        return str(path)
    return str(REPO_ROOT / path)


# ---------------------------------------------------------------------------
# Fabric CLI path resolution
# ---------------------------------------------------------------------------
# All source values come from env vars set by run.py.
# Every value is passed through _abs() so relative paths in .env work.

# FABRIC_CFG_PATH -- where the peer binary finds core.yaml
_FABRIC_CFG_PATH: str = _abs(
    os.environ.get("FABRIC_CFG_PATH",
                   str(REPO_ROOT / "fabric-samples" / "config"))
)

# PEER TLS CA -- --tlsRootCertFiles argument
# cfg.FABRIC_TLS_CERT is the peer's tls/ca.crt, set by run.py
_PEER_TLS_CA: str = _abs(cfg.FABRIC_TLS_CERT)

# ORDERER TLS CA -- --cafile argument
# Use FABRIC_ORDERER_TLS_CERT if set; otherwise derive from PEER TLS CA path.
def _resolve_orderer_tls_ca() -> str:
    if cfg.FABRIC_ORDERER_TLS_CERT:
        return _abs(cfg.FABRIC_ORDERER_TLS_CERT)
    # Derive: FABRIC_TLS_CERT is
    #   crypto-config/peerOrganizations/org1.example.com/peers/peer0.../tls/ca.crt
    # parents[0]=tls  [1]=peer0...  [2]=peers  [3]=org1...  [4]=peerOrganizations  [5]=crypto-config
    try:
        peer_ca = Path(_PEER_TLS_CA)  # already absolute
        crypto_root = peer_ca.parents[5]
        return str(
            crypto_root
            / "ordererOrganizations"
            / "example.com"
            / "orderers"
            / "orderer.example.com"
            / "msp"
            / "tlscacerts"
            / "tlsca.example.com-cert.pem"
        )
    except Exception:
        return str(Path(_PEER_TLS_CA).parent / "ca.crt")

_ORDERER_TLS_CA: str = _resolve_orderer_tls_ca()

# ADMIN MSP PATH -- CORE_PEER_MSPCONFIGPATH
# Must be the ADMIN USER msp/ directory (not the peer node msp/).
# Source priority:
#   1. FABRIC_ADMIN_MSP_PATH env var (explicit, set by some run.py variants)
#   2. Derive from FABRIC_SIGN_CERT: the admin signing cert lives at
#      msp/signcerts/cert.pem, so parent.parent == msp/
def _resolve_admin_msp() -> str:
    if cfg.FABRIC_ADMIN_MSP_PATH:
        return _abs(cfg.FABRIC_ADMIN_MSP_PATH)
    # FABRIC_SIGN_CERT e.g.:
    #   crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/signcerts/cert.pem
    # parent      = signcerts/
    # parent.parent = msp/   <-- exactly what CORE_PEER_MSPCONFIGPATH needs
    sign_cert = Path(_abs(cfg.FABRIC_SIGN_CERT))
    return str(sign_cert.parent.parent)

_ADMIN_MSP_PATH: str = _resolve_admin_msp()


def _log_fabric_paths() -> None:
    """Print resolved absolute paths + existence at startup."""
    log.info("Fabric CLI paths (all absolute):")
    for label, p in [
        ("FABRIC_CFG_PATH  ", _FABRIC_CFG_PATH),
        ("PEER_TLS_CA      ", _PEER_TLS_CA),
        ("ORDERER_TLS_CA   ", _ORDERER_TLS_CA),
        ("ADMIN_MSP_PATH   ", _ADMIN_MSP_PATH),
    ]:
        log.info("  %s = %s  exists=%s", label, p, Path(p).exists())
    log.info("  FABRIC_PEER_ENDPOINT = %s", cfg.FABRIC_PEER_ENDPOINT)
    log.info("  FABRIC_MSP_ID        = %s", cfg.FABRIC_MSP_ID)
    log.info("  FABRIC_CHANNEL       = %s", cfg.FABRIC_CHANNEL)
    log.info("  FABRIC_CHAINCODE     = %s", cfg.FABRIC_CHAINCODE)


def _peer_env() -> dict:
    """Environment dict passed to every `peer` subprocess call."""
    env = os.environ.copy()
    env["FABRIC_CFG_PATH"]             = _FABRIC_CFG_PATH
    env["CORE_PEER_TLS_ENABLED"]       = "true"
    env["CORE_PEER_LOCALMSPID"]        = cfg.FABRIC_MSP_ID
    env["CORE_PEER_ADDRESS"]           = cfg.FABRIC_PEER_ENDPOINT
    env["CORE_PEER_MSPCONFIGPATH"]     = _ADMIN_MSP_PATH
    env["CORE_PEER_TLS_ROOTCERT_FILE"] = _PEER_TLS_CA
    return env


def _submit_to_fabric(event: SecurityEvent) -> str:
    """
    Invoke LogEvent chaincode via `peer chaincode invoke`.
    Returns tx-id string. Raises RuntimeError on failure (caller retries).
    """
    payload_str = json.dumps(event.to_ledger_dict(), default=str)
    invoke_spec = json.dumps({"Args": ["LogEvent", payload_str]})

    cmd = [
        "peer", "chaincode", "invoke",
        "-o",  "orderer.example.com:7050",
        "--ordererTLSHostnameOverride", "orderer.example.com",
        "--tls",
        "--cafile",           _ORDERER_TLS_CA,
        "-C",                 cfg.FABRIC_CHANNEL,
        "-n",                 cfg.FABRIC_CHAINCODE,
        "-c",                 invoke_spec,
        "--peerAddresses",    cfg.FABRIC_PEER_ENDPOINT,
        "--tlsRootCertFiles", _PEER_TLS_CA,
        "--waitForEvent",
        "--waitForEventTimeout", f"{cfg.FABRIC_INVOKE_TIMEOUT_S}s",
    ]

    result = subprocess.run(
        cmd,
        env=_peer_env(),
        capture_output=True,
        text=True,
        timeout=cfg.FABRIC_INVOKE_TIMEOUT_S + 10,
    )

    combined = result.stdout + result.stderr

    if result.returncode != 0:
        raise RuntimeError(
            f"peer chaincode invoke failed (rc={result.returncode}): "
            f"{result.stderr.strip()[:500]}"
        )

    # Parse real tx-id from peer output: "...txid [<txid>] committed..."
    tx_id = ""
    for line in combined.splitlines():
        if "txid" in line.lower() and "[" in line:
            try:
                start = line.index("[") + 1
                end   = line.index("]", start)
                tx_id = line[start:end].strip()
                break
            except ValueError:
                pass

    if not tx_id:
        tx_id = "cli-" + hashlib.sha256(payload_str.encode()).hexdigest()[:32]

    log.debug("peer invoke stdout: %s", result.stdout.strip()[:200])
    log.debug("peer invoke stderr: %s", result.stderr.strip()[:200])
    return tx_id


# -- ECDSA signing (agent identity) ------------------------------------------
_agent_private_key: Optional[ec.EllipticCurvePrivateKey] = None
_agent_identity: Optional[str] = None


def _load_agent_key():
    global _agent_private_key, _agent_identity
    if _agent_private_key is not None:
        return
    with open(_abs(cfg.AGENT_KEY_PATH), "rb") as f:
        _agent_private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
    with open(_abs(cfg.AGENT_CERT_PATH), "rb") as f:
        cert_pem = f.read()
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    _agent_identity = cert.subject.rfc4514_string()


def _sign(data: bytes) -> str:
    _load_agent_key()
    sig = _agent_private_key.sign(data, ec.ECDSA(hashes.SHA256()))  # type: ignore
    return sig.hex()


# -- Redis helpers ------------------------------------------------------------
_redis_client: Optional[redis.Redis] = None


def _get_redis() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(cfg.REDIS_URL, decode_responses=True)
    return _redis_client


def _write_to_redis(event: SecurityEvent) -> None:
    r        = _get_redis()
    event_id = str(event.event_id)
    key      = cfg.REDIS_KEY_PREFIX + event_id
    record   = json.dumps(event.to_ledger_dict(), default=str)

    pipe = r.pipeline()
    pipe.set(key, record, ex=cfg.REDIS_TTL_S)
    ts = event.timestamp.timestamp()
    pipe.zadd(cfg.REDIS_IDX_ASSET + event.asset_id,       {event_id: ts})
    pipe.zadd(cfg.REDIS_IDX_SEV   + event.severity.value, {event_id: ts})
    pipe.execute()
    log.info("Redis write OK  event_id=%s", event_id)


# -- DLQ producer -------------------------------------------------------------
_dlq_producer: Optional[Producer] = None


def _get_dlq_producer() -> Producer:
    global _dlq_producer
    if _dlq_producer is None:
        _dlq_producer = Producer({"bootstrap.servers": cfg.KAFKA_BOOTSTRAP_SERVERS})
    return _dlq_producer


def _send_to_dlq(raw: bytes, reason: str) -> None:
    prod    = _get_dlq_producer()
    dlq_msg = json.dumps({"reason": reason,
                          "original": raw.decode("utf-8", errors="replace")})
    prod.produce(cfg.KAFKA_TOPIC_DLQ, value=dlq_msg.encode())
    prod.flush()
    log.error("DLQ: sent message  reason=%s", reason)


# -- Core pipeline ------------------------------------------------------------

def process_message(raw: bytes) -> None:
    try:
        event = SecurityEvent.from_kafka_bytes(raw)
    except Exception as exc:
        raise ValueError(f"Schema validation failed: {exc}") from exc

    log.info("Processing event_id=%s asset=%s severity=%s",
             event.event_id, event.asset_id, event.severity.value)

    payload_bytes = event.canonical_bytes()

    cid, sha256_hex = add_and_pin(payload_bytes)
    event.ipfs_cid = cid
    event.sha256   = sha256_hex

    if not fetch_and_verify(cid, sha256_hex):
        raise IPFSError(f"IPFS round-trip verify failed for CID {cid}")

    _load_agent_key()
    event.agent_identity  = _agent_identity
    event.agent_signature = _sign(payload_bytes)

    tx_id       = _submit_to_fabric(event)
    event.tx_id = tx_id
    log.info("Fabric commit OK  tx_id=%s  event_id=%s", tx_id, event.event_id)

    _write_to_redis(event)


# -- Main consumer loop -------------------------------------------------------

def main() -> None:
    log.info("blockchain-logger starting  REPO_ROOT=%s", REPO_ROOT)
    _log_fabric_paths()

    if not shutil.which("peer"):
        log.error("'peer' binary not found on PATH")
        sys.exit(1)

    missing = [
        p for p in [_PEER_TLS_CA, _ORDERER_TLS_CA, _ADMIN_MSP_PATH]
        if not Path(p).exists()
    ]
    if missing:
        log.error("Critical Fabric paths missing on disk:")
        for p in missing:
            log.error("  MISSING: %s", p)
        log.error(
            "Tip: ensure FABRIC_TLS_CERT, FABRIC_SIGN_CERT (and optionally "
            "FABRIC_ORDERER_TLS_CERT, FABRIC_ADMIN_MSP_PATH) in .env point "
            "to the correct files under crypto-config/. Relative paths are "
            "resolved against the repo root: %s", REPO_ROOT
        )
        sys.exit(1)

    consumer = Consumer({
        "bootstrap.servers":  cfg.KAFKA_BOOTSTRAP_SERVERS,
        "group.id":           cfg.KAFKA_CONSUMER_GROUP,
        "auto.offset.reset":  "earliest",
        "enable.auto.commit": "false",
    })
    consumer.subscribe([cfg.KAFKA_TOPIC_EVENTS])
    log.info("Subscribed to topic %s", cfg.KAFKA_TOPIC_EVENTS)

    _running = True

    def _stop(sig, frame):  # type: ignore
        nonlocal _running
        log.info("Signal %s -- shutting down", sig)
        _running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT,  _stop)

    max_retries  = cfg.FABRIC_MAX_RETRIES
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
        succeeded  = False

        for attempt in range(1, max_retries + 1):
            try:
                process_message(raw)
                succeeded = True
                break
            except ValueError as exc:
                log.error("Unrecoverable error (attempt %d): %s", attempt, exc)
                _send_to_dlq(raw, str(exc))
                succeeded = True
                break
            except Exception as exc:
                log.warning("Transient error (attempt %d/%d): %s",
                            attempt, max_retries, exc)
                traceback.print_exc()
                if attempt < max_retries:
                    sleep_s = backoff_base * (2 ** (attempt - 1))
                    log.info("Retrying in %.1f s ...", sleep_s)
                    time.sleep(sleep_s)
                else:
                    log.error("All %d retries exhausted -- DLQ", max_retries)
                    _send_to_dlq(raw, f"max retries exceeded: {exc}")
                    succeeded = True

        if succeeded:
            consumer.commit(message=msg, asynchronous=False)
            log.debug("Kafka offset committed  partition=%s offset=%s",
                      msg.partition(), msg.offset())

    consumer.close()
    log.info("blockchain-logger stopped")


if __name__ == "__main__":
    main()
