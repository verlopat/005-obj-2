"""Audit API - REST interface for querying the blockchain audit trail."""
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, Histogram, make_asgi_app
import time

from config import config
from query_service import query_service
from report_service import report_service
from schemas import (
    AuditEventRecord, AuditTrailRequest, ComplianceFramework,
    ComplianceReport, HealthResponse, IntegrityCheckResult, SeverityQueryRequest,
)

logging.basicConfig(level=getattr(logging, config.log_level),
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

QUERIES_TOTAL = Counter("audit_queries_total", "Total audit queries", ["endpoint"])
QUERY_LATENCY = Histogram("audit_query_latency_seconds", "Query latency",
                          buckets=[.01, .05, .1, .5, 1, 5])


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Audit API starting")
    yield
    logger.info("Audit API stopping")


app = FastAPI(title="Security Audit API",
              description="Query blockchain audit trail and generate compliance reports",
              version="1.0.0", lifespan=lifespan)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/metrics", make_asgi_app())


@app.get("/healthz", response_model=HealthResponse)
async def health():
    return HealthResponse(status="ok", fabric_connected=query_service.is_healthy())


@app.get("/api/v1/events/{event_id}", response_model=AuditEventRecord)
async def get_event(event_id: str):
    QUERIES_TOTAL.labels(endpoint="get_event").inc()
    event = query_service.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
    return event


@app.post("/api/v1/audit/trail", response_model=List[AuditEventRecord])
async def get_audit_trail(req: AuditTrailRequest):
    QUERIES_TOTAL.labels(endpoint="audit_trail").inc()
    start = time.perf_counter()
    events = query_service.get_event_history(
        asset_id=req.asset_id,
        start_time=req.start_time,
        end_time=req.end_time,
        limit=req.limit,
    )
    QUERY_LATENCY.observe(time.perf_counter() - start)
    return events


@app.post("/api/v1/audit/by-severity", response_model=List[AuditEventRecord])
async def get_by_severity(req: SeverityQueryRequest):
    QUERIES_TOTAL.labels(endpoint="by_severity").inc()
    return query_service.get_events_by_severity(
        severity=req.severity,
        start_time=req.start_time,
        end_time=req.end_time,
        limit=req.limit,
    )


@app.post("/api/v1/compliance/report", response_model=ComplianceReport)
async def generate_report(
    framework: ComplianceFramework,
    asset_id: Optional[str] = None,
    days: int = Query(default=30, ge=1, le=365),
):
    QUERIES_TOTAL.labels(endpoint="compliance_report").inc()
    end = datetime.utcnow()
    start = end - timedelta(days=days)
    if asset_id:
        events = query_service.get_event_history(asset_id=asset_id, start_time=start, end_time=end, limit=1000)
    else:
        events = []
    return report_service.generate(framework, events, start, end)


if __name__ == "__main__":
    uvicorn.run("app:app", host=config.api_host, port=config.api_port, workers=config.api_workers)
