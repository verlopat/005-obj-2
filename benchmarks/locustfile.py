"""Locust load test for the detector-adapter ingestion API."""
import random
import uuid
from locust import HttpUser, task, between


SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CATEGORIES = ["DDOS", "INTRUSION", "DATA_EXFILTRATION", "RANSOMWARE", "ANOMALY"]
PROVIDERS = ["AWS", "Azure", "GCP"]
REGIONS = ["us-east-1", "eu-west-1", "ap-southeast-1"]


def random_event():
    return {
        "event_id": str(uuid.uuid4()),
        "asset_id": f"asset-{random.randint(1, 100)}",
        "cloud_provider": random.choice(PROVIDERS),
        "region": random.choice(REGIONS),
        "severity": random.choice(SEVERITIES),
        "attack_category": random.choice(CATEGORIES),
        "description": f"Automated load test event {uuid.uuid4()}",
        "source_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "detection_confidence": round(random.uniform(0.6, 1.0), 2),
        "model_version": "v1.0",
    }


class DetectorUser(HttpUser):
    wait_time = between(0.1, 0.5)

    @task(8)
    def ingest_single_event(self):
        self.client.post("/api/v1/events", json=random_event(),
                         name="POST /api/v1/events")

    @task(2)
    def ingest_batch(self):
        batch_size = random.randint(5, 20)
        self.client.post("/api/v1/events/batch",
                         json={"events": [random_event() for _ in range(batch_size)]},
                         name="POST /api/v1/events/batch")

    @task(1)
    def health_check(self):
        self.client.get("/healthz", name="GET /healthz")
