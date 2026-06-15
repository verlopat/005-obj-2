"""Locust load test for the detector-adapter ingestion endpoint."""
import random
import uuid
from locust import HttpUser, task, between

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CATEGORIES = ["DDOS", "INTRUSION", "DATA_EXFILTRATION", "ANOMALY", "RANSOMWARE"]
PROVIDERS = ["AWS", "GCP", "Azure"]
REGIONS   = ["us-east-1", "eu-west-1", "ap-southeast-1"]

def generate_event():
    return {
        "asset_id": f"asset-{random.randint(1, 500)}",
        "cloud_provider": random.choice(PROVIDERS),
        "region": random.choice(REGIONS),
        "severity": random.choice(SEVERITIES),
        "attack_category": random.choice(CATEGORIES),
        "description": f"Automated load test event {uuid.uuid4()}",
        "source_ip": f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
        "detection_confidence": round(random.uniform(0.5, 1.0), 3),
        "model_version": "v1.0",
    }

class SecurityEventUser(HttpUser):
    wait_time = between(0.05, 0.2)
    host = "http://localhost:8000"

    @task(10)
    def ingest_single_event(self):
        self.client.post("/api/v1/events", json=generate_event(),
                         name="POST /api/v1/events")

    @task(2)
    def ingest_batch_events(self):
        batch = {"events": [generate_event() for _ in range(random.randint(5, 20))]}
        self.client.post("/api/v1/events/batch", json=batch,
                         name="POST /api/v1/events/batch")

    @task(1)
    def health_check(self):
        self.client.get("/healthz", name="GET /healthz")
