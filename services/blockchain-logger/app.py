"""
services/blockchain-logger/app.py

Kafka -> IPFS -> Hyperledger Fabric -> Redis pipeline.

Fabric transport: peer CLI subprocess (shell=False, no SDK, Python-3.14-safe).
All cert/key paths resolved to absolute strings anchored at REPO_ROOT so
relative values in .env work regardless of process working directory.
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
# REPO_ROOT resolution
# ---------------------------------------------------------------------------
# Priority:
#   1. BLOCKCHAIN_LOGGER_REPO_ROOT env var  (set by run.py -- most reliable)
#   2. Path(__file__).resolve() walk-up     (fallback when running directly)
#
# Using an env var lets run.py inject the exact absolute path it already
# knows, bypassing any special-character issues in __file__ resolution
# (e.g. parentheses in directory names on some shells).

_repo_from_env = os.environ.get("BLOCKCHAIN_LOGGER_REPO_ROOT", "").strip()
if _repo_from_env:
    REPO_ROOT = Path(_repo_from_env).resolve()
else:
    # app.py -> blockchain-logger/ -> services/ -> <repo root>
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
    - Absolute paths are returned unchanged.
    - Paths starting with ~ are expanded via expanduser().
    - Relative paths are resolved against REPO_ROOT (not process cwd).
    """
    if not p:
        return p
    path = Path(p)
    if str(p).startswith("~"):
        return str(path.expanduser().resolve())
    if path.is_absolute():
        return str(path)
    return str(REPO_ROOT / path)


# ---------------------------------------------------------------------------
# Fabric CLI path resolution
# ---------------------------------------------------------------------------

_FABRIC_CFG_PATH: str = _abs(
    os.environ.get("FABRIC_CFG_PATH",
                   str(REPO_ROOT / "fabric-samples" / "config"))
)

# Peer TLS CA -- --tlsRootCertFiles
_PEER_TLS_CA: str = _abs(cfg.FABRIC_TLS_CERT)

# Orderer TLS CA -- --cafile
def _resolve_orderer_tls_ca() -> str:
    if cfg.FABRIC_ORDERER_TLS_CERT:
        return _abs(cfg.FABRIC_ORDERER_TLS_CERT)
    # Derive from peer TLS CA (already absolute):
    # crypto-config/peerOrganizations/org1.example.com/peers/peer0.../tls/ca.crt
    # parents: [0]=tls [1]=peer0.. [2]=peers [3]=org1.. [4]=peerOrgs [5]=crypto-config
    try:
        crypto_root = Path(_PEER_TLS_CA).parents[5]
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

# Admin MSP path -- CORE_PEER_MSPCONFIGPATH (must be Admin USER msp/, not peer msp/)
def _resolve_admin_msp() -> str:
    if cfg.FABRIC_ADMIN_MSP_PATH:
        return _abs(cfg.FABRIC_ADMIN_MSP_PATH)
    # FABRIC_SIGN_CERT: .../users/Admin@org1.example.com/msp/signcerts/cert.pem
    # parent.parent == msp/
    return str(Path(_abs(cfg.FABRIC_SIGN_CERT)).parent.parent)

_ADMIN_MSP_PATH: str = _resolve_admin_msp()

# Orderer address (no hardcoding)
_ORDERER_ADDR: str = cfg.FABRIC_ORDERER_ENDPOINT  # e.g. orderer.example.com:7050


def _log_fabric_paths() -> None:
    log.info("REPO_ROOT = %s", REPO_ROOT)
    log.info("Fabric CLI paths (all absolute):")
    for label, p in [
        ("FABRIC_CFG_PATH ", _FABRIC_CFG_PATH),
        ("PEER_TLS_CA     ", _PEER_TLS_CA),
        ("ORDERER_TLS_CA  ", _ORDERER_TLS_CA),
        ("ADMIN_MSP_PATH  ", _ADMIN_MSP_PATH),
    ]:
        log.info("  %s = %s  exists=%s", label, p, Path(p).exists())
    log.info("  ORDERER_ADDR         = %s", _ORDERER_ADDR)
    log.info("  FABRIC_PEER_ENDPOINT = %s", cfg.FABRIC_PEER_ENDPOINT)
    log.info("  FABRIC_MSP_ID        = %s", cfg.FABRIC_MSP_ID)
    log.info("  FABRIC_CHANNEL       = %s", cfg.FABRIC_CHANNEL)
    log.info("  FABRIC_CHAINCODE     = %s", cfg.FABRIC_CHAINCODE)


def _peer_env() -> dict:
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
    Uses shell=False with an explicit list -- each element is passed
    directly to execvp(), no shell interpretation, safe with any path.
    """
    payload_str = json.dumps(event.to_ledger_dict(), default=str)
    invoke_spec = json.dumps({"Args": ["LogEvent", payload_str]})

    # Extract just the hostname for --ordererTLSHostnameOverride
    orderer_host = _ORDERER_ADDR.split(":")[0]

    cmd = [
        "peer", "chaincode", "invoke",
        "-o",  _ORDERER_ADDR,
        "--ordererTLSHostnameOverride", orderer_host,
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
        shell=False,          # explicit: no shell, no special-char interpretation
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

    # Parse real tx-id: "...txid [<txid>] committed..."
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

    log.debug("peer stdout: %s", result.stdout.strip()[:200])
    log.debug("peer stderr: %s", result.stderr.strip()[:200])
    return tx_id


# -- ECDSA signing -----------------------------------------------------------
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


# -- Redis helpers -----------------------------------------------------------
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


# -- DLQ producer ------------------------------------------------------------
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


# -- Core pipeline -----------------------------------------------------------

def process_message(raw: bytes) -> None:
    try:
        event = SecurityEvent.from_kafka_bytes(raw)
    except Exception as exc:
        raise ValueError(f"Schema validation failed: {exc}") from exc

    log.info("Processing event_id=%s asset=%s severity=%s",
             event.event_id, event.asset_id, event.severity.value)

    payload_bytes = event.canonical_bytes()

    cid, sha256_hex = add_and_pin(payload_bytes)
    event.ipfs_cid  = cid
    event.sha256    = sha256_hex

    if not fetch_and_verify(cid, sha256_hex):
        raise IPFSError(f"IPFS round-trip verify failed for CID {cid}")

    _load_agent_key()
    event.agent_identity  = _agent_identity
    event.agent_signature = _sign(payload_bytes)

    tx_id       = _submit_to_fabric(event)
    event.tx_id = tx_id
    log.info("Fabric commit OK  tx_id=%s  event_id=%s", tx_id, event.event_id)

    _write_to_redis(event)


# -- Main consumer loop ------------------------------------------------------

def main() -> None:
    log.info("blockchain-logger starting")
    _log_fabric_paths()

    if not shutil.which("peer"):
        log.error("'peer' binary not found on PATH")
        sys.exit(1)

    missing = [p for p in [_PEER_TLS_CA, _ORDERER_TLS_CA, _ADMIN_MSP_PATH]
               if not Path(p).exists()]
    if missing:
        log.error("Critical Fabric paths missing on disk:")
        for p in missing:
            log.error("  MISSING: %s", p)
        log.error(
            "Paths are resolved relative to REPO_ROOT=%s. "
            "Set BLOCKCHAIN_LOGGER_REPO_ROOT in .env to override.",
            REPO_ROOT
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
                log.error("Unrecoverable (attempt %d): %s", attempt, exc)
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
