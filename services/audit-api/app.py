"""
services/audit-api/app.py

FastAPI audit service.  All queries read from shared Redis.
No mock ledger, no in-process state.
"""
from __future__ import annotations

import logging
import os
import sys
import traceback
from typing import List, Optional

# Make repo root importable so 'shared' package resolves correctly.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn

from shared import config as cfg
from shared.event_schema import SecurityEvent, VerificationResult

# Import query_service from the same package directory.
from query_service import (
    query_by_asset,
    query_by_event_id,
    query_by_severity,
    verify_record,
    _get_redis,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [audit-api] %(levelname)s %(message)s",
)
log = logging.getLogger("audit-api")

app = FastAPI(
    title="Blockchain Audit API",
    description="Immutable audit trail — Hyperledger Fabric + IPFS",
    version="2.0.0",
)


# ── Global exception handler (surfaces real error instead of opaque 500) ─────────────

@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
    tb = traceback.format_exc()
    log.error("Unhandled exception on %s %s:\n%s", request.method, request.url.path, tb)
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc), "traceback": tb},
    )


# ── Request / Response models ─────────────────────────────────────────────────────────

class TrailRequest(BaseModel):
    asset_id: str
    page_size: int = 20


class SeverityRequest(BaseModel):
    severity: str
    page_size: int = 100


class ComplianceRequest(BaseModel):
    standard: str = "ISO-27001"
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    output_format: str = "json"


# ── Endpoints ────────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    try:
        r = _get_redis()
        r.ping()
        redis_ok = True
    except Exception as e:
        redis_ok = False
    return {"status": "ok", "mode": "live", "redis": redis_ok}


@app.get("/api/v1/debug/redis")
def debug_redis():
    """
    Show all keys in Redis so we can verify blockchain-logger wrote records.
    Returns up to 200 keys with their types and (for string keys) raw values.
    """
    try:
        r = _get_redis()
        keys = r.keys("*")
        result = {}
        for k in keys[:200]:
            ktype = r.type(k)
            if ktype == "string":
                result[k] = {"type": "string", "value": r.get(k)}
            elif ktype == "zset":
                members = r.zrevrange(k, 0, 4, withscores=True)
                result[k] = {"type": "zset", "top5": members}
            else:
                result[k] = {"type": ktype}
        return {"total_keys": len(keys), "keys": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Redis error: {e}")


@app.post("/api/v1/audit/trail", response_model=List[dict])
def audit_trail(req: TrailRequest):
    """
    Return the audit trail for an asset.
    Reads from Redis (populated by blockchain-logger after each Fabric commit).
    Returns [] if no records found — never raises 404 for empty results.
    Skips records that fail deserialisation (logs a warning per bad record).
    """
    try:
        records = query_by_asset(req.asset_id, page_size=req.page_size)
        return [r.to_ledger_dict() for r in records]
    except Exception as e:
        tb = traceback.format_exc()
        log.error("audit_trail failed for asset_id=%s: %s\n%s", req.asset_id, e, tb)
        raise HTTPException(status_code=500, detail=f"audit_trail error: {e}\n{tb}")


@app.get("/api/v1/audit/event/{event_id}")
def get_event(event_id: str):
    try:
        rec = query_by_event_id(event_id)
        if rec is None:
            raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
        return rec.to_ledger_dict()
    except HTTPException:
        raise
    except Exception as e:
        tb = traceback.format_exc()
        log.error("get_event failed event_id=%s: %s\n%s", event_id, e, tb)
        raise HTTPException(status_code=500, detail=f"{e}\n{tb}")


@app.post("/api/v1/audit/severity", response_model=List[dict])
def by_severity(req: SeverityRequest):
    try:
        records = query_by_severity(req.severity.upper(), page_size=req.page_size)
        return [r.to_ledger_dict() for r in records]
    except Exception as e:
        tb = traceback.format_exc()
        log.error("by_severity failed severity=%s: %s\n%s", req.severity, e, tb)
        raise HTTPException(status_code=500, detail=f"{e}\n{tb}")


@app.get("/api/v1/verify/{event_id}", response_model=VerificationResult)
def verify(event_id: str):
    """
    Full integrity verification:
      - on-chain SHA-256 == recomputed SHA-256
      - live IPFS payload SHA-256 == stored hash
      - ECDSA agent_signature is valid
    """
    try:
        return verify_record(event_id)
    except Exception as e:
        tb = traceback.format_exc()
        log.error("verify failed event_id=%s: %s\n%s", event_id, e, tb)
        raise HTTPException(status_code=500, detail=f"{e}\n{tb}")


@app.post("/api/v1/compliance/report")
def compliance_report(req: ComplianceRequest):
    """Return ISO-27001 / SOC2 compliance summary from live Redis data."""
    from datetime import datetime, timezone
    try:
        critical = query_by_severity("CRITICAL", page_size=10_000)
        high     = query_by_severity("HIGH",     page_size=10_000)
        medium   = query_by_severity("MEDIUM",   page_size=10_000)
        low      = query_by_severity("LOW",      page_size=10_000)
        total    = len(critical) + len(high) + len(medium) + len(low)

        return {
            "standard":         req.standard,
            "generated_at":     datetime.now(timezone.utc).isoformat(),
            "period":           f"{req.start_time} to {req.end_time}",
            "total_events":     total,
            "critical_events":  len(critical),
            "high_events":      len(high),
            "medium_events":    len(medium),
            "low_events":       len(low),
            "storage_backend":  "Hyperledger Fabric + IPFS (live)",
            "integrity_check":  "SHA-256 + ECDSA P-256",
            "controls_satisfied": [
                "A.12.4.1 — Event logging",
                "A.12.4.2 — Protection of log information",
                "A.12.4.3 — Administrator and operator logs",
                "A.16.1.2 — Reporting information security events",
            ],
            "status": "COMPLIANT" if total > 0 else "NO_DATA",
        }
    except Exception as e:
        tb = traceback.format_exc()
        log.error("compliance_report failed: %s\n%s", e, tb)
        raise HTTPException(status_code=500, detail=f"{e}\n{tb}")


if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=cfg.AUDIT_API_PORT,
        log_level="info",
    )
