#!/usr/bin/env python3
"""
mock_blockchain_logger.py
--------------------------
PROTOTYPE / DEV-ONLY — NOT PRODUCTION

This file is a simulation-only prototype that:
  - generates a local RSA keypair (NOT Fabric CA credentials)
  - fakes IPFS with a placeholder CID
  - prints "Transaction submitted" without actually submitting to Fabric

It is kept here for reference ONLY and must NOT be used as evidence
that Objective 2 is operational.  For the real pipeline, use:
    live_blockchain_logger.py

DO NOT cite this file in your thesis.
"""

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone

print("WARNING: This is a MOCK prototype. Use live_blockchain_logger.py for real Fabric submission.")


def _mock_sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def simulate_pipeline():
    event_id = f"evt_{int(time.time())}_{uuid.uuid4().hex[:8]}"
    payload = {
        "event_id":            event_id,
        "timestamp":           datetime.now(timezone.utc).isoformat(),
        "severity":            "HIGH",
        "attack_category":     "DDoS",
        "detection_confidence": 0.98,
        "cloud_asset_id":      "vm-prod-01",
        "model_version":       "obj1-cnn-lstm-transformer-v1",
    }

    fake_cid  = "Qm" + _mock_sha256(event_id)[:44]
    fake_hash = _mock_sha256(json.dumps(payload, sort_keys=True))

    print(f"[MOCK] Event ID   : {event_id}")
    print(f"[MOCK] IPFS CID   : {fake_cid}  (SIMULATED — not real IPFS)")
    print(f"[MOCK] SHA-256    : {fake_hash}")
    print("[MOCK] Transaction submitted  (SIMULATED — no Fabric node contacted)")
    print("[MOCK] Chain-of-custody claim: NOT valid for thesis evidence.")


if __name__ == "__main__":
    simulate_pipeline()
