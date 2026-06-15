#!/usr/bin/env python3
"""
benchmark.py
------------
Objective 2 KPI Benchmark Suite

Measures and records evidence for all six Objective 2 success metrics:
  1. Blockchain Transaction Throughput  ≥ 1,000 TPS under sustained load
  2. Log Commit Latency                 ≤ 500 ms  (95th percentile)
  3. On-Chain Storage Overhead          ≤ 1 KB per event (hash + metadata only)
  4. Log Integrity Verification         0% failure rate across all stored events
  5. Smart Contract Audit               static analysis pass (to be run externally)
  6. Forensic Audit Trail               chain-of-custody report generation

Results are written to:
  results/benchmark_results.json
  results/benchmark_report.csv

Usage:
  python benchmark.py [--events 200] [--asset vm-prod-01]

Dependencies:
  pip install requests statistics
"""

import argparse
import json
import logging
import math
import os
import statistics
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BENCH] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

RESULTS_DIR = Path("results")


# ---------------------------------------------------------------------------
# Metric 1 + 2: Throughput and Latency
# ---------------------------------------------------------------------------

def run_throughput_latency_test(
    n_events: int = 200,
    cloud_asset_id: str = "vm-bench-01",
) -> dict:
    """
    Submit *n_events* security events sequentially, measuring per-event
    commit latency (time from invoke call to ledger confirmation).

    Returns a dict with throughput (TPS), latency percentiles, and raw data.
    """
    from live_blockchain_logger import (
        build_event_payload,
        get_signer,
        load_or_create_aes_key,
        store_off_chain_ipfs_encrypted,
        invoke_chaincode,
    )

    aes_key = load_or_create_aes_key()
    signer  = get_signer()

    latencies: list[float] = []
    successes = 0
    wall_start = time.perf_counter()

    for i in range(n_events):
        payload = build_event_payload(
            cloud_asset_id=cloud_asset_id,
            attack_category="DDoS" if i % 3 == 0 else ("PortScan" if i % 3 == 1 else "PrivEsc"),
            detection_confidence=round(0.90 + (i % 10) * 0.009, 3),
        )

        if signer:
            agent_identity  = signer.get_agent_identity()
            agent_signature = signer.sign_event(payload)
        else:
            agent_identity  = "dev-agent-unsigned"
            agent_signature = "unsigned"

        ipfs_cid, payload_hash, _ = store_off_chain_ipfs_encrypted(payload, aes_key)
        if not ipfs_cid:
            log.warning("[BENCH] IPFS failed for event %d — skipping", i)
            continue

        t0 = time.perf_counter()
        record = invoke_chaincode(
            event_id             = payload["event_id"],
            payload_hash         = payload_hash,
            ipfs_cid             = ipfs_cid,
            timestamp            = payload["timestamp"],
            severity             = payload["severity"],
            attack_category      = payload["attack_category"],
            detection_confidence = payload["detection_confidence"],
            model_version        = payload["model_version"],
            agent_identity       = agent_identity,
            agent_signature      = agent_signature,
            cloud_asset_id       = payload["cloud_asset_id"],
        )
        t1 = time.perf_counter()

        if record:
            latency_ms = (t1 - t0) * 1000
            latencies.append(latency_ms)
            successes += 1
            log.info("[BENCH] Event %d/%d  latency=%.1f ms", i + 1, n_events, latency_ms)
        else:
            log.warning("[BENCH] Event %d failed", i)

    wall_end = time.perf_counter()
    elapsed  = wall_end - wall_start
    tps      = successes / elapsed if elapsed > 0 else 0

    result = {
        "metric": "throughput_latency",
        "n_submitted": n_events,
        "n_succeeded": successes,
        "success_rate": round(successes / n_events * 100, 1),
        "elapsed_seconds": round(elapsed, 2),
        "tps": round(tps, 2),
        "tps_kpi": ">= 1000 TPS",
        "tps_pass": tps >= 1000,
        "latency_mean_ms":   round(statistics.mean(latencies),   1) if latencies else None,
        "latency_p95_ms":    round(_percentile(latencies, 95),    1) if latencies else None,
        "latency_p99_ms":    round(_percentile(latencies, 99),    1) if latencies else None,
        "latency_max_ms":    round(max(latencies),                1) if latencies else None,
        "latency_kpi":       "<= 500 ms p95",
        "latency_p95_pass":  _percentile(latencies, 95) <= 500    if latencies else False,
        "raw_latencies_ms":  [round(l, 2) for l in latencies],
    }
    log.info(
        "[BENCH] Throughput: %.1f TPS  |  Latency p95: %.1f ms  |  Pass: TPS=%s Lat=%s",
        result["tps"],
        result["latency_p95_ms"] or -1,
        result["tps_pass"],
        result["latency_p95_pass"],
    )
    return result


# ---------------------------------------------------------------------------
# Metric 3: On-chain storage size
# ---------------------------------------------------------------------------

def measure_on_chain_storage() -> dict:
    """
    Serialise a representative SecurityEvent struct to JSON and measure
    the byte size.  Must be ≤ 1024 bytes (1 KB) per the Objective 2 KPI.
    """
    representative_event = {
        "event_id":             "evt_1718438400_ab12cd34",
        "payload_hash":         "a" * 64,   # SHA-256 hex
        "ipfs_cid":             "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
        "timestamp":            "2025-06-15T12:00:00Z",
        "severity":             "HIGH",
        "attack_category":      "DDoS",
        "detection_confidence": 0.98,
        "model_version":        "obj1-cnn-lstm-transformer-v1",
        "agent_identity":       "detection-agent-01",
        "agent_signature":      "b" * 128,  # typical DER-encoded ECDSA P-256 sig hex
        "cloud_asset_id":       "vm-prod-01",
    }

    serialised    = json.dumps(representative_event, separators=(",", ":"))
    size_bytes    = len(serialised.encode("utf-8"))
    kpi_threshold = 1024   # 1 KB

    result = {
        "metric":          "on_chain_storage",
        "size_bytes":      size_bytes,
        "kpi":             "<= 1024 bytes (1 KB)",
        "kpi_pass":        size_bytes <= kpi_threshold,
        "serialised_json": serialised,
    }
    log.info(
        "[BENCH] On-chain event size: %d bytes  KPI pass: %s",
        size_bytes, result["kpi_pass"],
    )
    return result


# ---------------------------------------------------------------------------
# Metric 4: Integrity verification
# ---------------------------------------------------------------------------

def run_integrity_verification_test(cloud_asset_id: str = "vm-bench-01") -> dict:
    """
    Query all events for *cloud_asset_id*, then re-verify each IPFS payload.
    Target: 0% integrity verification failures.
    """
    from audit_query import AuditQueryClient

    client = AuditQueryClient()
    events = client.get_event_history(cloud_asset_id)

    total    = len(events)
    passed   = 0
    failures = []

    for ev in events:
        ok = client.verify_ipfs_integrity(ev)
        if ok:
            passed += 1
        else:
            failures.append(ev.get("event_id", "<unknown>"))

    failure_rate = ((total - passed) / total * 100) if total > 0 else 0.0

    result = {
        "metric":               "integrity_verification",
        "total_events":         total,
        "passed":               passed,
        "failed":               total - passed,
        "failure_rate_pct":     round(failure_rate, 2),
        "kpi":                  "0% failure rate",
        "kpi_pass":             failure_rate == 0.0,
        "failed_event_ids":     failures,
    }
    log.info(
        "[BENCH] Integrity: %d/%d passed  failure_rate=%.1f%%  KPI pass: %s",
        passed, total, failure_rate, result["kpi_pass"],
    )
    return result


# ---------------------------------------------------------------------------
# Metric 6: Forensic audit trail chain-of-custody
# ---------------------------------------------------------------------------

def run_chain_of_custody_report(cloud_asset_id: str = "vm-bench-01") -> dict:
    """
    Generate a chain-of-custody report for *cloud_asset_id*,
    demonstrating end-to-end traceability from agent identity to ledger record.
    """
    from audit_query import AuditQueryClient

    client  = AuditQueryClient()
    events  = client.get_event_history(cloud_asset_id)
    report  = client.export_report(events, fmt="json")

    RESULTS_DIR.mkdir(exist_ok=True)
    report_path = RESULTS_DIR / f"chain_of_custody_{cloud_asset_id}.json"
    report_path.write_text(report, encoding="utf-8")

    # Verify that every event has a non-empty agent_identity and agent_signature
    non_repudiable = sum(
        1 for e in events
        if e.get("agent_identity") and e.get("agent_signature")
           and e["agent_identity"] != "dev-agent-unsigned"
    )

    result = {
        "metric":               "chain_of_custody",
        "cloud_asset_id":       cloud_asset_id,
        "total_events":         len(events),
        "non_repudiable":       non_repudiable,
        "report_path":          str(report_path),
        "kpi":                  "Demonstrable unbroken chain-of-custody",
        "kpi_pass":             len(events) > 0 and non_repudiable == len(events),
    }
    log.info(
        "[BENCH] Chain-of-custody: %d/%d events non-repudiable  report=%s",
        non_repudiable, len(events), report_path,
    )
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _percentile(data: list[float], p: float) -> float:
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * p / 100
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_data[int(k)]
    return sorted_data[f] * (c - k) + sorted_data[c] * (k - f)


# ---------------------------------------------------------------------------
# Main: run all benchmarks and write results
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Objective 2 KPI Benchmark")
    parser.add_argument("--events", type=int, default=200,
                        help="Number of events for throughput/latency test (default 200)")
    parser.add_argument("--asset",  default="vm-bench-01",
                        help="Cloud asset ID for integrity + custody tests")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(exist_ok=True)
    all_results = {}

    # Metric 2 + 1: Throughput and latency
    log.info("\n=== Metric 1+2: Throughput and Latency ===")
    all_results["throughput_latency"] = run_throughput_latency_test(
        n_events=args.events,
        cloud_asset_id=args.asset,
    )

    # Metric 3: Storage overhead
    log.info("\n=== Metric 3: On-Chain Storage Overhead ===")
    all_results["on_chain_storage"] = measure_on_chain_storage()

    # Metric 4: Integrity
    log.info("\n=== Metric 4: IPFS Integrity Verification ===")
    all_results["integrity_verification"] = run_integrity_verification_test(args.asset)

    # Metric 6: Chain-of-custody
    log.info("\n=== Metric 6: Forensic Chain-of-Custody ===")
    all_results["chain_of_custody"] = run_chain_of_custody_report(args.asset)

    # Write JSON results
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    results_path = RESULTS_DIR / f"benchmark_results_{ts}.json"
    results_path.write_text(
        json.dumps(all_results, indent=2, default=str), encoding="utf-8"
    )
    log.info("\nResults written to %s", results_path)

    # Summary
    log.info("\n===== Objective 2 KPI Summary =====")
    kpi_map = {
        "throughput_latency":   ("tps_pass", "latency_p95_pass"),
        "on_chain_storage":     ("kpi_pass",),
        "integrity_verification": ("kpi_pass",),
        "chain_of_custody":     ("kpi_pass",),
    }
    all_pass = True
    for metric, keys in kpi_map.items():
        for k in keys:
            val = all_results.get(metric, {}).get(k, False)
            status = "✅ PASS" if val else "❌ FAIL"
            log.info("  %-40s %s", f"{metric}.{k}", status)
            if not val:
                all_pass = False

    log.info("\n  Overall: %s", "✅ ALL KPIs PASS" if all_pass else "❌ SOME KPIs FAIL")
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
