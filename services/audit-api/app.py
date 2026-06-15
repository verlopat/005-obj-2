"""Audit API — FastAPI service exposing audit trail queries and compliance reports."""
import logging
from datetime import datetime
from typing import Literal, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from prometheus_client import Counter, make_asgi_app

from config import config
from fabric_query import fabric_query
from report_generator import report_generator

logging.basicConfig(level=getattr(logging, config.log_level),
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

QUERIES = Counter("audit_api_queries_total", "Audit API query count", ["endpoint"])

app = FastAPI(title="Security Audit API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/metrics", make_asgi_app())


@app.get("/healthz")
def health():
    return {"status": "ok"}


@app.get("/api/v1/events/{event_id}")
def get_event(event_id: str):
    QUERIES.labels(endpoint="get_event").inc()
    result = fabric_query.get_event(event_id)
    if not result:
        raise HTTPException(404, detail=f"Event {event_id} not found")
    return result


@app.get("/api/v1/audit/history")
def get_history(
    asset_id: str,
    start: str = Query(..., description="ISO8601 start datetime"),
    end:   str = Query(..., description="ISO8601 end datetime"),
):
    QUERIES.labels(endpoint="history").inc()
    return fabric_query.query_history(asset_id, start, end)


@app.get("/api/v1/audit/severity")
def get_by_severity(
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    start: str = Query(...),
    end:   str = Query(...),
):
    QUERIES.labels(endpoint="by_severity").inc()
    return fabric_query.query_by_severity(severity, start, end)


@app.get("/api/v1/reports")
def generate_report(
    framework: Literal["ISO27001", "SOC2", "NIST_SP_800_92", "GENERIC"] = "GENERIC",
    start: str = Query(...),
    end:   str = Query(...),
    fmt: Literal["json", "csv"] = "json",
    severity: Optional[Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]] = None,
):
    QUERIES.labels(endpoint="report").inc()
    if severity:
        events = fabric_query.query_by_severity(severity, start, end)
    else:
        result = fabric_query.get_all_events()
        events = result.get("records", []) if isinstance(result, dict) else result
    content = report_generator.generate(events, framework, start, end, fmt)
    media_type = "application/json" if fmt == "json" else "text/csv"
    filename   = f"compliance_report_{framework}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.{fmt}"
    return Response(content=content, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


if __name__ == "__main__":
    uvicorn.run("app:app", host=config.api_host, port=config.api_port, workers=config.api_workers)
