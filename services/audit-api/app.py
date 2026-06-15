"""Audit API — FastAPI service for blockchain audit trail queries and compliance reports."""
import logging
from datetime import datetime
from typing import List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.responses import PlainTextResponse

from config import config
from query_service import query_service
from report_service import report_service
from schemas import (
    AuditTrailRequest, ComplianceReport, ComplianceReportRequest,
    ComplianceStandard, EventRecord, IntegrityCheckRequest,
    IntegrityCheckResult, SeverityQueryRequest,
)

logging.basicConfig(level=getattr(logging, config.log_level),
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Blockchain Audit API",
    description="Query immutable security event records from Hyperledger Fabric",
    version="1.0.0",
)

@app.get("/healthz")
async def health():
    return {"status": "ok", "version": "1.0.0"}

@app.post("/api/v1/audit/trail", response_model=List[EventRecord])
async def get_audit_trail(req: AuditTrailRequest):
    try:
        return query_service.query_audit_trail(
            asset_id=req.asset_id,
            start_time=req.start_time,
            end_time=req.end_time,
            page_size=req.page_size,
        )
    except Exception as exc:
        logger.exception("Audit trail query failed")
        raise HTTPException(status_code=500, detail=str(exc))

@app.post("/api/v1/audit/severity", response_model=List[EventRecord])
async def query_by_severity(req: SeverityQueryRequest):
    try:
        return query_service.query_by_severity(
            severity=req.severity,
            start_time=req.start_time,
            end_time=req.end_time,
            page_size=req.page_size,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.get("/api/v1/audit/event/{event_id}", response_model=EventRecord)
async def get_event(event_id: str):
    record = query_service.get_event(event_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
    return record

@app.post("/api/v1/compliance/report", response_model=ComplianceReport)
async def generate_report(req: ComplianceReportRequest):
    try:
        report = report_service.generate_report(
            standard=req.standard,
            start_time=req.start_time,
            end_time=req.end_time,
            asset_ids=req.asset_ids,
        )
        if req.output_format == "csv":
            csv_data = report_service.export_csv(report.events)
            return PlainTextResponse(content=csv_data, media_type="text/csv")
        return report
    except Exception as exc:
        logger.exception("Report generation failed")
        raise HTTPException(status_code=500, detail=str(exc))

if __name__ == "__main__":
    uvicorn.run("app:app", host=config.api_host, port=config.api_port)
