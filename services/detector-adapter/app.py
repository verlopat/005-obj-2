"""Detector Adapter — FastAPI ingestion endpoint publishing events to Kafka."""
import logging
import time
from contextlib import asynccontextmanager
from typing import List

import uvicorn
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, Histogram, REGISTRY, make_asgi_app

from config import config
from producer import producer
from schemas import (
    BatchEventRequest, BatchEventResponse,
    EventResponse, HealthResponse, SecurityEventRequest,
)

logging.basicConfig(level=getattr(logging, config.log_level),
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def _counter(name: str, doc: str, labels=None):
    """Return existing Counter if already registered, else create a new one."""
    collectors = list(REGISTRY._names_to_collectors.keys())
    # prometheus_client adds '_total' and '_created' suffixes
    if f"{name}_total" in collectors or name in collectors:
        return REGISTRY._names_to_collectors.get(
            f"{name}_total",
            REGISTRY._names_to_collectors.get(name)
        )
    kwargs = {"labelnames": labels} if labels else {}
    return Counter(name, doc, **kwargs)


def _histogram(name: str, doc: str, buckets=None):
    collectors = list(REGISTRY._names_to_collectors.keys())
    if f"{name}_bucket" in collectors or name in collectors:
        return REGISTRY._names_to_collectors.get(name)
    kwargs = {"buckets": buckets} if buckets else {}
    return Histogram(name, doc, **kwargs)


EVENTS_PRODUCED = _counter(
    "detector_events_produced",
    "Events produced to Kafka",
    labels=["severity"],
)
EVENTS_FAILED = _counter(
    "detector_events_failed",
    "Events that failed to produce",
)
INGESTION_LAT = _histogram(
    "detector_ingestion_latency_seconds",
    "Ingestion latency",
    buckets=[.001, .005, .01, .05, .1, .5, 1],
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Detector adapter starting")
    yield
    logger.info("Detector adapter shutting down")
    producer.flush()
    producer.close()


app = FastAPI(title="Security Event Detector Adapter", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)
app.mount("/metrics", make_asgi_app())


@app.get("/healthz", response_model=HealthResponse)
async def health_check():
    kafka_ok = producer.is_healthy()
    return HealthResponse(status="ok" if kafka_ok else "degraded", kafka_connected=kafka_ok)


@app.post("/api/v1/events", response_model=EventResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(event: SecurityEventRequest):
    start = time.perf_counter()
    try:
        producer.produce(str(event.event_id), event.dict())
        if EVENTS_PRODUCED is not None:
            EVENTS_PRODUCED.labels(severity=event.severity.value).inc()
        if INGESTION_LAT is not None:
            INGESTION_LAT.observe(time.perf_counter() - start)
        return EventResponse(event_id=str(event.event_id), status="accepted")
    except Exception as exc:
        if EVENTS_FAILED is not None:
            EVENTS_FAILED.inc()
        logger.exception("Failed to produce event %s", event.event_id)
        try:
            producer.produce_dlq(str(event.event_id), event.dict(), str(exc))
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="Failed to enqueue event")


@app.post("/api/v1/events/batch", response_model=BatchEventResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_batch(batch: BatchEventRequest):
    results, accepted, rejected = [], 0, 0
    for event in batch.events:
        try:
            producer.produce(str(event.event_id), event.dict())
            if EVENTS_PRODUCED is not None:
                EVENTS_PRODUCED.labels(severity=event.severity.value).inc()
            results.append(EventResponse(event_id=str(event.event_id), status="accepted"))
            accepted += 1
        except Exception as exc:
            if EVENTS_FAILED is not None:
                EVENTS_FAILED.inc()
            results.append(EventResponse(event_id=str(event.event_id), status="rejected", message=str(exc)))
            rejected += 1
    producer.flush(timeout=5.0)
    return BatchEventResponse(accepted=accepted, rejected=rejected, results=results)


if __name__ == "__main__":
    uvicorn.run("app:app", host=config.api_host, port=config.api_port, workers=1)
