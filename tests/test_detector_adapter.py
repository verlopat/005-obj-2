"""Unit and integration tests for the detector-adapter service."""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "services", "detector-adapter"))


@pytest.fixture
def client():
    with patch("producer.SecurityEventProducer._get_producer"):
        from app import app
        return TestClient(app)


class TestHealthCheck:
    def test_health_ok(self, client):
        with patch("app.producer.is_healthy", return_value=True):
            resp = client.get("/healthz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["kafka_connected"] is True

    def test_health_degraded(self, client):
        with patch("app.producer.is_healthy", return_value=False):
            resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "degraded"


class TestEventIngestion:
    VALID_EVENT = {
        "asset_id": "cloud-asset-1",
        "cloud_provider": "AWS",
        "region": "us-east-1",
        "severity": "HIGH",
        "attack_category": "DDOS",
        "description": "DDoS traffic detected",
        "detection_confidence": 0.97,
        "model_version": "v1.0",
    }

    def test_ingest_valid_event_returns_202(self, client):
        with patch("app.producer.produce"):
            resp = client.post("/api/v1/events", json=self.VALID_EVENT)
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "accepted"
        assert "event_id" in data

    def test_ingest_missing_required_field_returns_422(self, client):
        bad_event = {k: v for k, v in self.VALID_EVENT.items() if k != "asset_id"}
        resp = client.post("/api/v1/events", json=bad_event)
        assert resp.status_code == 422

    def test_ingest_invalid_severity_returns_422(self, client):
        bad = dict(self.VALID_EVENT, severity="EXTREME")
        resp = client.post("/api/v1/events", json=bad)
        assert resp.status_code == 422

    def test_kafka_failure_returns_500(self, client):
        with patch("app.producer.produce", side_effect=Exception("Kafka unavailable")), \
             patch("app.producer.produce_dlq"):
            resp = client.post("/api/v1/events", json=self.VALID_EVENT)
        assert resp.status_code == 500


class TestBatchIngestion:
    def test_batch_accepts_multiple_events(self, client):
        events = [
            {
                "asset_id": f"asset-{i}",
                "cloud_provider": "GCP",
                "region": "eu-west-1",
                "severity": "MEDIUM",
                "description": f"Test event {i}",
            }
            for i in range(5)
        ]
        with patch("app.producer.produce"), patch("app.producer.flush"):
            resp = client.post("/api/v1/events/batch", json={"events": events})
        assert resp.status_code == 202
        data = resp.json()
        assert data["accepted"] == 5
        assert data["rejected"] == 0
