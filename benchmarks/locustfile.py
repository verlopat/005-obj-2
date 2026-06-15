"""Locust load test for the detector-adapter ingestion endpoint."""
import random
import uuid
from datetime import datetime

from locust import HttpUser, TaskSet, between, task

SEVERITIES  = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CATEGORIES  = ["DDOS", "INTRUSION", "DATA_EXFILTRATION", "ANOMALY", "PRIVILEGE_ESCALATION"]
PROVIDERS   = ["AWS", "GCP", "AZURE"]
REGIONS     = ["us-east-1", "eu-west-1", "ap-southeast-1"]


def _make_event() -> dict:
    return {
        "asset_id":             f"vm-{random.randint(1, 500):04d}",
        "cloud_provider":       random.choice(PROVIDERS),
        "region":               random.choice(REGIONS),
        "severity":             random.choice(SEVERITIES),
        "attack_category":      random.choice(CATEGORIES),
        "description":          f"Automated load-test event {uuid.uuid4()}",
        "source_ip":            f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}",
        "detection_confidence": round(random.uniform(0.5, 1.0), 3),
        "model_version":        "v1.0",
        "timestamp":            datetime.utcnow().isoformat() + "Z",
    }


class DetectorTasks(TaskSet):
    @task(9)
    def post_single_event(self):
        self.client.post("/api/v1/events", json=_make_event(),
                         name="POST /api/v1/events")

    @task(1)
    def post_batch_events(self):
        batch_size = random.randint(2, 20)
        self.client.post("/api/v1/events/batch",
                         json={"events": [_make_event() for _ in range(batch_size)]},
                         name="POST /api/v1/events/batch")

    @task(1)
    def health_check(self):
        self.client.get("/healthz", name="GET /healthz")


class DetectorUser(HttpUser):
    tasks      = [DetectorTasks]
    wait_time  = between(0.05, 0.5)
    host       = "http://localhost:8000"
