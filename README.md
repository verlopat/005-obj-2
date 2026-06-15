# Blockchain-Based Immutable Audit Trail for AI-Driven Cloud Security

> **Research Objective 2** — Non-repudiable, tamper-evident logging of security events using Hyperledger Fabric + IPFS

## Architecture Overview

```
Cloud Environments (AWS / GCP / Azure)
        │
        ▼
 Detector Adapter  ──►  Kafka  ──►  Blockchain Logger  ──►  Fabric + IPFS
        │                                                          │
        └──────────────────────────────────►  Audit API  ◄────────┘
                                                  │
                                     Compliance Scheduler
```

## Repository Structure

```
├── chaincode/            # Hyperledger Fabric Go chaincode
├── services/
│   ├── detector-adapter/    # FastAPI ingest → Kafka producer
│   ├── blockchain-logger/   # Kafka consumer → IPFS + Fabric
│   ├── audit-api/           # FastAPI audit query + compliance reports
│   └── compliance-scheduler/ # APScheduler automated reporting
├── messaging/            # Kafka topic scripts
├── observability/        # Prometheus + Grafana configs
├── benchmarks/           # k6 + Locust load tests, storage estimates
├── kubernetes/           # K8s manifests with HPA
├── tests/                # Unit + integration test suite
├── scripts/              # Bootstrap, destroy, healthcheck
├── docs/                 # Architecture, threat model, runbook, API spec
├── configtx.yaml         # Fabric channel/genesis config
├── docker-compose.yml    # Full local stack
├── Makefile              # Developer workflow
└── .env.example          # Environment variable template
```

## Quick Start

```bash
# 1. Clone and configure
cp .env.example .env

# 2. Start the full stack
make up

# 3. Check all services are healthy
make health

# 4. Create Kafka topics
make topics

# 5. Run tests
make test

# 6. Run load benchmark
make benchmark
```

## Ingest a Security Event

```bash
curl -X POST http://localhost:8000/api/v1/events \
  -H 'Content-Type: application/json' \
  -d '{
    "asset_id": "aws-ec2-i-1234567890",
    "cloud_provider": "AWS",
    "region": "us-east-1",
    "severity": "HIGH",
    "attack_category": "DDOS",
    "description": "Volumetric DDoS: 45Gbps inbound",
    "detection_confidence": 0.97,
    "model_version": "v2.1"
  }'
```

## Generate a Compliance Report

```bash
curl -X POST http://localhost:8001/api/v1/compliance/report \
  -H 'Content-Type: application/json' \
  -d '{"standard":"ISO-27001","start_time":"2025-01-01T00:00:00Z","end_time":"2025-12-31T23:59:59Z","output_format":"json"}'
```

## Security Properties

| Property | Mechanism |
|---|---|
| Immutability | Fabric append-only ledger |
| Non-repudiation | ECDSA P-256 signatures |
| Integrity | SHA-256 stored on-chain, verified vs IPFS |
| Access control | Org1MSP certificate auth in chaincode |
| Auditability | Full history queryable by asset + time window |

## Objective 2 Coverage

- [x] Immutable on-chain security event records (Fabric chaincode)
- [x] Hybrid storage: metadata on-chain, full payload on IPFS
- [x] ECDSA P-256 non-repudiation signatures
- [x] SHA-256 integrity verification (chain ↔ IPFS)
- [x] Org1MSP access control in chaincode
- [x] CouchDB rich queries: by asset, severity, time window
- [x] Compliance reports: ISO 27001, SOC 2, NIST SP 800-92
- [x] Automated scheduled reporting (daily/weekly)
- [x] Kafka-based event pipeline with DLQ
- [x] Horizontal autoscaling (HPA for all services)
- [x] Prometheus metrics + Grafana dashboards + alert rules
- [x] Load tests: k6 (500 VU) + Locust, storage growth estimates
- [x] Full unit + integrity test suite

## ⚠️ Security Notice

The file `secret.key` was previously committed to this repository. **Rotate any credentials it contained immediately.** To purge it from git history:
```bash
git filter-repo --path secret.key --invert-paths
```
