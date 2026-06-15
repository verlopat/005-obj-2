"""Detector Adapter — FastAPI ingestion endpoint publishing events to Kafka.

Now includes a real Isolation Forest anomaly detector (detector.py) that
replaces hardcoded detection_confidence values with genuine model scores.
"""
import logging
import time
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, Histogram, make_asgi_app

from config import config
from producer import producer
from schemas import (
    BatchEventRequest, BatchEventResponse,
    EventResponse, HealthResponse, SecurityEventRequest,
)

logging.basicConfig(level=getattr(logging, config.log_level),
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ── Load real anomaly detector ───────────────────────────────────────────────
try:
    from detector import detector as _anomaly_detector
    logger.info("Isolation Forest detector loaded (%s)", _anomaly_detector.model_version())
except Exception as _det_err:
    logger.warning("Could not load anomaly detector: %s — using passthrough", _det_err)
    _anomaly_detector = None


def _score_event(event_dict: dict) -> dict:
    """Enrich event with real model-derived confidence + model version."""
    if _anomaly_detector is not None:
        event_dict["detection_confidence"] = _anomaly_detector.score(event_dict)
        event_dict["model_version"]        = _anomaly_detector.model_version()
    return event_dict


# ── Prometheus metrics — safe against duplicate-registration on hot reload ──
def _safe_counter(name, doc, labelnames=None):
    try:
        return Counter(name, doc, labelnames or [])
    except ValueError:
        from prometheus_client import REGISTRY
        for collector in REGISTRY._names_to_collectors.values():
            if hasattr(collector, '_name') and collector._name in (name, name + '_total'):
                return collector
        return None


def _safe_histogram(name, doc, buckets=None):
    kwargs = {'buckets': buckets} if buckets else {}
    try:
        return Histogram(name, doc, **kwargs)
    except ValueError:
        from prometheus_client import REGISTRY
        return REGISTRY._names_to_collectors.get(name)


EVENTS_PRODUCED = _safe_counter(
    "detector_events_produced_total",
    "Events produced to Kafka",
    labelnames=["severity"],
)
EVENTS_FAILED = _safe_counter(
    "detector_events_failed_total",
    "Events that failed to produce",
)
INGESTION_LAT = _safe_histogram(
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
        event_dict = _score_event(event.model_dump())
        producer.produce(str(event.event_id), event_dict)
        if EVENTS_PRODUCED is not None:
            EVENTS_PRODUCED.labels(severity=event.severity.value).inc()
        if INGESTION_LAT is not None:
            INGESTION_LAT.observe(time.perf_counter() - start)
        return EventResponse(
            event_id=str(event.event_id),
            status="accepted",
            detection_confidence=event_dict.get("detection_confidence"),
            model_version=event_dict.get("model_version"),
        )
    except Exception as exc:
        if EVENTS_FAILED is not None:
            EVENTS_FAILED.inc()
        logger.exception("Failed to produce event %s", event.event_id)
        try:
            producer.produce_dlq(str(event.event_id), event.model_dump(), str(exc))
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="Failed to enqueue event")


@app.post("/api/v1/events/batch", response_model=BatchEventResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_batch(batch: BatchEventRequest):
    results, accepted, rejected = [], 0, 0
    for event in batch.events:
        try:
            event_dict = _score_event(event.model_dump())
            producer.produce(str(event.event_id), event_dict)
            if EVENTS_PRODUCED is not None:
                EVENTS_PRODUCED.labels(severity=event.severity.value).inc()
            results.append(EventResponse(
                event_id=str(event.event_id),
                status="accepted",
                detection_confidence=event_dict.get("detection_confidence"),
                model_version=event_dict.get("model_version"),
            ))
            accepted += 1
        except Exception as exc:
            if EVENTS_FAILED is not None:
                EVENTS_FAILED.inc()
            results.append(EventResponse(
                event_id=str(event.event_id), status="rejected", message=str(exc)
            ))
            rejected += 1
    producer.flush(timeout=5.0)
    return BatchEventResponse(accepted=accepted, rejected=rejected, results=results)


if __name__ == "__main__":
    uvicorn.run("app:app", host=config.api_host, port=config.api_port, workers=1)
