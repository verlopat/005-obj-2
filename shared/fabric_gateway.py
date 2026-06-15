"""Thin wrapper around the Fabric peer CLI for query operations.

The blockchain-logger submits transactions via its own fabric_client.py.
This module is used by the audit-api query service to read from the ledger.

All functions raise RuntimeError on failure — callers must not swallow these.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from shared.config import (
    FABRIC_CHANNEL, FABRIC_CHAINCODE, FABRIC_PEER_ENDPOINT,
    FABRIC_TLS_CERT, FABRIC_MSP_ID, FABRIC_SIGN_CERT,
)

log = logging.getLogger(__name__)


def _peer_env() -> Dict[str, str]:
    cfg = os.environ.get("FABRIC_CFG_PATH", "fabric-config")
    msp_dir = str(Path(FABRIC_SIGN_CERT).parent.parent)
    return {
        **os.environ,
        "FABRIC_CFG_PATH":           cfg,
        "CORE_PEER_TLS_ENABLED":     "true",
        "CORE_PEER_LOCALMSPID":      FABRIC_MSP_ID,
        "CORE_PEER_ADDRESS":         FABRIC_PEER_ENDPOINT,
        "CORE_PEER_MSPCONFIGPATH":   msp_dir,
        "CORE_PEER_TLS_ROOTCERT_FILE": FABRIC_TLS_CERT,
    }


def _query(func: str, *args: str) -> Any:
    """Invoke a chaincode query function and return parsed JSON."""
    cmd = [
        "peer", "chaincode", "query",
        "-C", FABRIC_CHANNEL,
        "-n", FABRIC_CHAINCODE,
        "-c", json.dumps({"function": func, "Args": list(args)}),
    ]
    result = subprocess.run(cmd, env=_peer_env(), capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(
            f"Fabric query {func} failed (rc={result.returncode}): {result.stderr[:400]}"
        )
    raw = result.stdout.strip()
    if not raw:
        return []
    return json.loads(raw)


def query_by_asset(asset_id: str, page_size: int = 20) -> List[dict]:
    """Query chaincode QueryByAsset — returns list of AuditRecord dicts."""
    records = _query("QueryByAsset", asset_id, str(page_size))
    if isinstance(records, dict):
        records = [records]
    return records or []


def query_by_severity(
    severity: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    page_size: int = 20,
) -> List[dict]:
    """Query chaincode QueryBySeverity."""
    records = _query(
        "QueryBySeverity",
        severity,
        start_time or "",
        end_time or "",
        str(page_size),
    )
    if isinstance(records, dict):
        records = [records]
    return records or []


def get_event(event_id: str) -> Optional[dict]:
    """Query chaincode GetEvent — returns single record or None."""
    try:
        return _query("GetEvent", event_id)
    except RuntimeError as exc:
        if "NOT_FOUND" in str(exc) or "does not exist" in str(exc):
            return None
        raise
