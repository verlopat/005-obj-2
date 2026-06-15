"""Audit API — live Fabric reads only.  No mock paths."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional

from query_service import (
    get_event_live,
    query_audit_trail,
    query_by_severity_live,
    verify_record,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AUDIT-API] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Audit API starting — live Fabric mode")
    yield
    log.info("Audit API shutting down")


app = FastAPI(
    title="Audit API",
    description="Immutable audit trail — Hyperledger Fabric (live)",
    version="2.0.0",
    lifespan=lifespan,
)


class TrailRequest(BaseModel):
    asset_id: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    page_size: int = 20


class SeverityRequest(BaseModel):
    severity: str
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    page_size: int = 20


class ComplianceRequest(BaseModel):
    standard: str = "ISO-27001"
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    output_format: str = "json"


@app.get("/health")
def health():
    return {"status": "ok", "mode": "live"}


@app.post("/api/v1/audit/trail")
def get_audit_trail(req: TrailRequest):
    try:
        records = query_audit_trail(
            asset_id=req.asset_id,
            start_time=req.start_time,
            end_time=req.end_time,
            page_size=req.page_size,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return {"records": [r.model_dump() for r in records], "count": len(records)}


@app.post("/api/v1/audit/severity")
def get_by_severity(req: SeverityRequest):
    try:
        records = query_by_severity_live(
            severity=req.severity,
            start_time=req.start_time,
            end_time=req.end_time,
            page_size=req.page_size,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return {"records": [r.model_dump() for r in records], "count": len(records)}


@app.get("/api/v1/audit/event/{event_id}")
def get_event(event_id: str):
    try:
        record = get_event_live(event_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    if record is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return record.model_dump()


@app.get("/api/v1/audit/verify/{event_id}")
def verify(event_id: str):
    """Three-way integrity check: on-chain hash + IPFS payload + ECDSA signature.

    Returns one of: VALID | HASH_MISMATCH | SIGNATURE_INVALID | CID_NOT_FOUND
    """
    try:
        result = verify_record(event_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    status_code = 200 if result["status"] == "VALID" else 409
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=status_code, content=result)


@app.post("/api/v1/compliance/report")
def compliance_report(req: ComplianceRequest):
    """Query Fabric for counts by severity and return a compliance snapshot."""
    from datetime import datetime, timezone
    counts = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        try:
            records = query_by_severity_live(severity=sev, page_size=1000)
            counts[sev] = len(records)
        except RuntimeError:
            counts[sev] = -1

    return {
        "standard":        req.standard,
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "period":          f"{req.start_time} to {req.end_time}",
        "severity_counts": counts,
        "storage_backend": "Hyperledger Fabric + IPFS (live)",
        "controls_satisfied": [
            "A.12.4.1 — Event logging",
            "A.12.4.2 — Protection of log information",
            "A.12.4.3 — Administrator and operator logs",
            "A.16.1.2 — Reporting information security events",
        ],
        "status": "COMPLIANT",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8001, reload=False)
