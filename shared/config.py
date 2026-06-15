"""
shared/config.py  —  Single source of truth for all runtime configuration.

All services import from here.  Required live variables raise RuntimeError
at import time if missing — there is no mock fallback in live mode.

Set LIVE_MODE=1 (default) to enforce all required variables.
Set LIVE_MODE=0 only for unit-test runs that mock every external call.
"""
from __future__ import annotations

import os
from pathlib import Path


def _require(name: str) -> str:
    """Return env var value or raise immediately — no silent fallback."""
    val = os.environ.get(name, "").strip()
    if not val:
        raise RuntimeError(
            f"[config] Required environment variable '{name}' is not set. "
            f"Set it in .env or export it before starting the service."
        )
    return val


def _optional(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


# ── Mode flag ────────────────────────────────────────────────────────────────
# LIVE_MODE=1  →  all required vars enforced, no mock fallback (default)
# LIVE_MODE=0  →  unit-test mode; callers must mock every external dependency
LIVE_MODE: bool = _optional("LIVE_MODE", "1") != "0"


# ── Kafka ────────────────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP_SERVERS: str = (
    _require("KAFKA_BOOTSTRAP_SERVERS") if LIVE_MODE
    else _optional("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
)
KAFKA_TOPIC_EVENTS: str    = _optional("KAFKA_TOPIC_EVENTS",   "security-events")
KAFKA_TOPIC_DLQ: str       = _optional("KAFKA_TOPIC_DLQ",      "security-events-dlq")
KAFKA_CONSUMER_GROUP: str  = _optional("KAFKA_CONSUMER_GROUP", "blockchain-logger")
# Offsets are committed only after successful Fabric+IPFS submission (see logger)
KAFKA_AUTO_COMMIT: bool    = False  # always manual — never change this


# ── Hyperledger Fabric ───────────────────────────────────────────────────────
FABRIC_PEER_ENDPOINT: str  = _optional("FABRIC_PEER_ENDPOINT", "localhost:7051")
FABRIC_CHANNEL: str        = _optional("FABRIC_CHANNEL",       "security-channel")
FABRIC_CHAINCODE: str      = _optional("FABRIC_CHAINCODE",     "security_logger")

# TLS cert paths — required in live mode
if LIVE_MODE:
    FABRIC_TLS_CERT: str   = _require("FABRIC_TLS_CERT")
    FABRIC_SIGN_CERT: str  = _require("FABRIC_SIGN_CERT")
    FABRIC_SIGN_KEY: str   = _require("FABRIC_SIGN_KEY")
    FABRIC_MSP_ID: str     = _require("FABRIC_MSP_ID")
else:
    FABRIC_TLS_CERT: str   = _optional("FABRIC_TLS_CERT")
    FABRIC_SIGN_CERT: str  = _optional("FABRIC_SIGN_CERT")
    FABRIC_SIGN_KEY: str   = _optional("FABRIC_SIGN_KEY")
    FABRIC_MSP_ID: str     = _optional("FABRIC_MSP_ID", "Org1MSP")

# Fabric lifecycle — used by run.py pre-flight check
FABRIC_ORDERER_ENDPOINT: str     = _optional("FABRIC_ORDERER_ENDPOINT",     "localhost:7050")
FABRIC_ORDERER_TLS_CERT: str     = _optional("FABRIC_ORDERER_TLS_CERT")
FABRIC_PEER_TLS_CERT: str        = _optional("FABRIC_PEER_TLS_CERT")
FABRIC_ADMIN_MSP_PATH: str       = _optional("FABRIC_ADMIN_MSP_PATH")
FABRIC_CC_VERSION: str           = _optional("FABRIC_CC_VERSION",  "1.0")
FABRIC_CC_SEQUENCE: str          = _optional("FABRIC_CC_SEQUENCE", "1")

# Retry policy for Fabric submissions
FABRIC_MAX_RETRIES: int          = int(_optional("FABRIC_MAX_RETRIES", "3"))
FABRIC_RETRY_BACKOFF_S: float    = float(_optional("FABRIC_RETRY_BACKOFF_S", "2.0"))
FABRIC_INVOKE_TIMEOUT_S: int     = int(_optional("FABRIC_INVOKE_TIMEOUT_S", "60"))


# ── IPFS ─────────────────────────────────────────────────────────────────────
IPFS_API_URL: str = (
    _require("IPFS_API_URL") if LIVE_MODE
    else _optional("IPFS_API_URL", "http://127.0.0.1:5001")
)
IPFS_TIMEOUT_S: int = int(_optional("IPFS_TIMEOUT_S", "30"))
# If True, also pin the CID via ipfs pin add after upload
IPFS_PIN: bool = _optional("IPFS_PIN", "1") == "1"


# ── Shared durable cache (Redis) ─────────────────────────────────────────────
# The blockchain logger writes committed records here so the audit-api can
# query them across process boundaries without querying the Fabric peer for
# every read request.  Required in live mode so the two services share state.
REDIS_URL: str = (
    _require("REDIS_URL") if LIVE_MODE
    else _optional("REDIS_URL", "redis://localhost:6379/0")
)
REDIS_TTL_S: int     = int(_optional("REDIS_TTL_S",     str(7 * 24 * 3600)))  # 7 days
REDIS_KEY_PREFIX: str = _optional("REDIS_KEY_PREFIX", "audit:event:")
REDIS_IDX_ASSET: str  = _optional("REDIS_IDX_ASSET",  "audit:idx:asset:")
REDIS_IDX_SEV: str    = _optional("REDIS_IDX_SEV",    "audit:idx:severity:")


# ── PKI / signing ─────────────────────────────────────────────────────────────
AGENT_KEY_PATH: str  = _optional("AGENT_KEY_PATH",  "crypto-config/agent/keystore/agent_sk")
AGENT_CERT_PATH: str = _optional("AGENT_CERT_PATH", "crypto-config/agent/signcerts/agent.pem")

# AES key for IPFS payload encryption — must live outside the repo
AES_KEY_PATH: str    = _optional("AES_KEY_PATH", ".aes_key")


# ── API service ports ─────────────────────────────────────────────────────────
DETECTOR_PORT: int  = int(_optional("DETECTOR_PORT",  "8000"))
AUDIT_API_PORT: int = int(_optional("AUDIT_API_PORT", "8001"))
LOGGER_PORT: int    = int(_optional("LOGGER_PORT",    "8002"))


# ── Convenience: print all live settings on import (debug) ───────────────────
def dump() -> dict:
    """Return a redacted config dict — safe to log."""
    return {
        "LIVE_MODE":                LIVE_MODE,
        "KAFKA_BOOTSTRAP_SERVERS":  KAFKA_BOOTSTRAP_SERVERS,
        "KAFKA_TOPIC_EVENTS":       KAFKA_TOPIC_EVENTS,
        "KAFKA_TOPIC_DLQ":          KAFKA_TOPIC_DLQ,
        "FABRIC_PEER_ENDPOINT":     FABRIC_PEER_ENDPOINT,
        "FABRIC_CHANNEL":           FABRIC_CHANNEL,
        "FABRIC_CHAINCODE":         FABRIC_CHAINCODE,
        "FABRIC_MSP_ID":            FABRIC_MSP_ID,
        "FABRIC_TLS_CERT":          "[set]" if FABRIC_TLS_CERT else "[MISSING]",
        "FABRIC_SIGN_CERT":         "[set]" if FABRIC_SIGN_CERT else "[MISSING]",
        "FABRIC_SIGN_KEY":          "[set]" if FABRIC_SIGN_KEY else "[MISSING]",
        "IPFS_API_URL":             IPFS_API_URL,
        "REDIS_URL":                REDIS_URL,
        "AGENT_KEY_PATH":           AGENT_KEY_PATH,
        "AGENT_CERT_PATH":          AGENT_CERT_PATH,
        "AES_KEY_PATH":             AES_KEY_PATH,
    }
