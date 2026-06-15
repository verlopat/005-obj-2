# Objective 2 — Blockchain-Based Tamper-Proof Security Event Logging

This repository implements **Objective 2** of the research project:
*Design and Integration of a Blockchain-Based Tamper-Proof Security Event Logging Architecture.*

---

## Architecture Overview

```
Detection Agent (Python)
    │
    ├─ pki_signer.py        ← ECDSA-sign event with X.509 cert (Fabric CA)
    ├─ ipfs_uploader.py     ← Upload full payload to IPFS, get (CID, SHA-256)
    └─ blockchain_logger.py ← Submit (hash + metadata) to Fabric via gRPC
           │
           ▼
    Hyperledger Fabric (Raft consensus, CouchDB state DB)
           │
           ├─ chaincode/security_logger.go
           │      ├─ LogSecurityEvent()
           │      ├─ VerifyEvent()
           │      ├─ QueryEventHistory()       ← time-window audit trail
           │      └─ QueryEventsBySeverity()   ← compliance reporting
           │
           └─ CouchDB  ←→  Rich JSON queries

    IPFS Node
    └─ Full event payloads (network features, confidence scores, metadata)
       On-chain: only SHA-256 hash + CID + metadata  (≤1 KB per event)

    audit_query.py  ← CLI/library for compliance reports (JSON/CSV)
                       ISO 27001 · SOC 2 · NIST SP 800-92
```

---

## Repository Structure

| Path | Description |
|---|---|
| `chaincode/security_logger.go` | Go chaincode — `LogSecurityEvent`, `VerifyEvent`, `QueryEventHistory`, `QueryEventsBySeverity` |
| `blockchain_logger.py` | Python agent — submits events to Fabric |
| `live_blockchain_logger.py` | Real-time streaming logger |
| `ipfs_uploader.py` | **NEW** — hybrid on-chain/off-chain storage via IPFS |
| `pki_signer.py` | **NEW** — ECDSA signing + X.509 non-repudiation |
| `audit_query.py` | **NEW** — audit trail querying and compliance report export |
| `docker-compose.yml` | **NEW** — Fabric CA, Orderer, 2× Peers, CouchDB, IPFS |
| `kubernetes/fabric-deployment.yaml` | **NEW** — Kubernetes manifests + HPA |
| `configtx.yaml` | **NEW** — channel/genesis block configuration |
| `scripts/enroll_agent.sh` | **NEW** — Fabric CA agent enrolment script |
| `deploy_objective_2.sh` | Full automated deployment script |
| `deploy_network_and_cc.sh` | Fabric network + chaincode deployment |

---

## Quick Start

### 1. Prerequisites

```bash
# Install Fabric binaries + Docker images
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.0
export PATH=$PATH:$(pwd)/fabric-samples/bin
```

### 2. Generate crypto materials

```bash
cryptogen generate --config=./crypto-config.yaml
configtxgen -profile TwoOrgsOrdererGenesis -channelID system-channel \
            -outputBlock channel-artifacts/genesis.block
configtxgen -profile TwoOrgsChannel -channelID mychannel \
            -outputCreateChannelTx channel-artifacts/mychannel.tx
```

### 3. Start the network

```bash
docker compose up -d
./deploy_network_and_cc.sh
```

### 4. Enrol a detection agent

```bash
bash scripts/enroll_agent.sh
```

### 5. Install Python dependencies

```bash
pip install cryptography ipfshttpclient requests hfc
```

### 6. Run the live logger

```bash
python live_blockchain_logger.py
```

### 7. Query the audit trail

```bash
# All events for a cloud asset (last 30 days)
python audit_query.py --asset vm-prod-01 --from 2025-01-01 --format csv --output report.csv

# All CRITICAL events
python audit_query.py --severity CRITICAL --format json

# Verify a specific event + IPFS payload integrity
python audit_query.py --event-id evt_abc123 --verify-ipfs
```

---

## Objective 2 Coverage

| Sub-component | Status |
|---|---|
| Enterprise Blockchain (Hyperledger Fabric 2.5, Raft) | ✅ |
| Go chaincode — LogSecurityEvent | ✅ |
| Go chaincode — VerifyEvent | ✅ |
| Go chaincode — QueryEventHistory | ✅ |
| Go chaincode — QueryEventsBySeverity | ✅ |
| Hybrid on-chain/off-chain storage (IPFS + SHA-256) | ✅ |
| Cryptographic event signing (ECDSA P-256) | ✅ |
| Non-repudiation (X.509 PKI via Fabric CA) | ✅ |
| Agent enrolment script (fabric-ca-client) | ✅ |
| Audit trail query interface (JSON/CSV export) | ✅ |
| Compliance reports (ISO 27001, SOC 2, NIST SP 800-92) | ✅ |
| Docker Compose deployment | ✅ |
| Kubernetes manifests + HPA | ✅ |
| Channel configuration (configtx.yaml) | ✅ |

---

## Security Notes

- **Never commit private keys.** `.gitignore` excludes `crypto-config/`, `*.key`, `*_sk`, `*.pem`.
- Rotate any keys that were previously committed to this repository.
- All agent credentials are issued by Fabric CA and stored only in `crypto-config/` (gitignored).
