# System Architecture

## Overview

This system implements **Research Objective 2**: a blockchain-based immutable audit trail for AI-driven cloud security event detection. It provides non-repudiable, tamper-evident logging of security events from heterogeneous cloud environments using Hyperledger Fabric.

```
┌─────────────────────────────────────────────────────────────────┐
│                     CLOUD ENVIRONMENTS                          │
│  AWS  │  GCP  │  Azure  │  On-Premises                         │
└─────────────┬───────────────────────────────────────────────────┘
              │ Security Events (REST)
              ▼
┌─────────────────────────────┐
│     Detector Adapter        │  FastAPI ingest → Kafka producer
│     (services/detector-     │  Idempotent, DLQ fallback
│      adapter/)              │  Prometheus metrics on :9090
└──────────────┬──────────────┘
               │ Kafka topic: security-events (12 partitions)
               ▼
┌─────────────────────────────┐
│     Blockchain Logger       │  Multi-threaded Kafka consumer
│     (services/blockchain-   │  IPFS upload → SHA-256 hash
│      logger/)               │  Fabric Gateway submission
└──────┬──────────┬───────────┘  ECDSA P-256 signing
       │          │
       ▼          ▼
┌──────────┐  ┌───────────────────────────────────────┐
│   IPFS   │  │      Hyperledger Fabric Network        │
│  (off-   │  │  Orderer (Raft) + 2× Peer (CouchDB)   │
│  chain   │  │  Chaincode: security_logger.go         │
│  store)  │  │  Channel: security-channel             │
└──────────┘  └───────────────┬───────────────────────┘
                              │ Query
                              ▼
             ┌────────────────────────────┐
             │        Audit API           │  FastAPI query + reports
             │   (services/audit-api/)    │  ISO 27001 / SOC 2 / NIST
             └────────────┬───────────────┘
                          │ Scheduled
                          ▼
             ┌────────────────────────────┐
             │  Compliance Scheduler      │  APScheduler
             │  (services/compliance-     │  Daily/weekly report jobs
             │   scheduler/)              │  Integrity spot checks
             └────────────────────────────┘
```

## Data Flow

1. **Ingest**: Security detection agents POST events to the Detector Adapter REST API.
2. **Queue**: Events are produced to Kafka topic `security-events` with idempotent producer (exactly-once semantics).
3. **Log**: Blockchain Logger workers consume events, upload the full payload to IPFS (returning CID), compute SHA-256, sign with ECDSA P-256, and submit `LogSecurityEvent` to the Hyperledger Fabric chaincode.
4. **Store**: The chaincode stores a compact on-chain record (event metadata + CID + hash) in CouchDB state DB. The full payload lives off-chain in IPFS.
5. **Query**: The Audit API exposes REST endpoints to query the immutable ledger by asset, severity, or time window, and to generate compliance reports.
6. **Schedule**: The Compliance Scheduler automatically generates daily/weekly reports and runs integrity spot checks (comparing on-chain SHA-256 with IPFS-fetched hash).

## Security Properties

| Property | Mechanism |
|---|---|
| Immutability | Hyperledger Fabric append-only ledger |
| Non-repudiation | ECDSA P-256 signatures on each event |
| Integrity | SHA-256 hash stored on-chain, verified against IPFS payload |
| Access control | Org1MSP membership enforced in chaincode |
| Confidentiality | TLS for all inter-service communication |
| Auditability | Full event history queryable by asset ID and time window |
