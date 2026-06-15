"""Single source of truth for environment flags.

All services import from here.  If a required live variable is missing
the process raises RuntimeError at import time — fast-fail, no silent mock.
"""
from __future__ import annotations

import os
import sys


def _require(name: str) -> str:
    """Return env var or raise with a clear message."""
    val = os.environ.get(name, "").strip()
    if not val:
        raise RuntimeError(
            f"Required environment variable {name!r} is not set.\n"
            f"Set it in .env or export it before starting the stack.\n"
            f"See .env.example for all required variables."
        )
    return val


def _optional(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


# ── Live/mock guard ─────────────────────────────────────────────────────────
# MOCK_MODE must be explicitly set to "1" to allow unit-test mock paths.
# Everything else is live.  The run.py live path never sets MOCK_MODE.
MOCK_MODE: bool = os.environ.get("MOCK_MODE", "0").strip() == "1"

if MOCK_MODE:
    # In mock/unit-test mode, provide harmless defaults so imports don't crash.
    FABRIC_PEER_ENDPOINT   = _optional("FABRIC_PEER_ENDPOINT",   "peer0.org1.example.com:7051")
    FABRIC_CHANNEL         = _optional("FABRIC_CHANNEL",         "security-channel")
    FABRIC_CHAINCODE       = _optional("FABRIC_CHAINCODE",       "security_logger")
    FABRIC_TLS_CERT        = _optional("FABRIC_TLS_CERT",        "")
    FABRIC_SIGN_CERT       = _optional("FABRIC_SIGN_CERT",       "")
    FABRIC_SIGN_KEY        = _optional("FABRIC_SIGN_KEY",        "")
    FABRIC_MSP_ID          = _optional("FABRIC_MSP_ID",          "Org1MSP")
    IPFS_API_URL           = _optional("IPFS_API_URL",           "http://127.0.0.1:5001")
    KAFKA_BOOTSTRAP        = _optional("KAFKA_BOOTSTRAP",        "localhost:9092")
    KAFKA_TOPIC            = _optional("KAFKA_TOPIC",            "security-events")
    KAFKA_DLQ_TOPIC        = _optional("KAFKA_DLQ_TOPIC",        "security-events-dlq")
    KAFKA_GROUP_ID         = _optional("KAFKA_GROUP_ID",         "blockchain-logger")
    AGENT_KEY_PATH         = _optional("AGENT_KEY_PATH",         "")
    AGENT_CERT_PATH        = _optional("AGENT_CERT_PATH",        "")
else:
    # Live mode — all required.  Missing any one raises RuntimeError immediately.
    FABRIC_PEER_ENDPOINT   = _require("FABRIC_PEER_ENDPOINT")
    FABRIC_CHANNEL         = _require("FABRIC_CHANNEL")
    FABRIC_CHAINCODE       = _require("FABRIC_CHAINCODE")
    FABRIC_TLS_CERT        = _require("FABRIC_TLS_CERT")
    FABRIC_SIGN_CERT       = _require("FABRIC_SIGN_CERT")
    FABRIC_SIGN_KEY        = _require("FABRIC_SIGN_KEY")
    FABRIC_MSP_ID          = _optional("FABRIC_MSP_ID", "Org1MSP")
    IPFS_API_URL           = _require("IPFS_API_URL")
    KAFKA_BOOTSTRAP        = _require("KAFKA_BOOTSTRAP")
    KAFKA_TOPIC            = _optional("KAFKA_TOPIC",  "security-events")
    KAFKA_DLQ_TOPIC        = _optional("KAFKA_DLQ_TOPIC", "security-events-dlq")
    KAFKA_GROUP_ID         = _optional("KAFKA_GROUP_ID", "blockchain-logger")
    AGENT_KEY_PATH         = _require("AGENT_KEY_PATH")
    AGENT_CERT_PATH        = _require("AGENT_CERT_PATH")

# Retry / backoff tuning (shared by logger worker)
KAFKA_MAX_RETRIES: int    = int(_optional("KAFKA_MAX_RETRIES",   "5"))
KAFKA_RETRY_BASE_S: float = float(_optional("KAFKA_RETRY_BASE_S", "1.0"))
KAFKA_RETRY_CAP_S: float  = float(_optional("KAFKA_RETRY_CAP_S",  "60.0"))
