# Objective 2 — Blockchain-Based Tamper-Proof Security Event Logging

Research project by **Gaddam Srikanth Reddy** (24EG305A08), supervised by Dr. Jothi Kumar. R, Anurag University, Hyderabad.

---

## Architecture

```
Objective 1 Model
  └─ anomaly event + confidence score + attack class
           │
           ▼
  live_blockchain_logger.py
    ├─ Step 1: Canonical event payload (attack_category, detection_confidence,
    │          cloud_asset_id, model_version — matching chaincode schema)
    ├─ Step 2: ECDSA sign with Fabric CA X.509 agent credentials (pki_signer.py)
    ├─ Step 3: AES-256-GCM encrypt full payload → upload to IPFS → get CID
    │          SHA-256(stored_bytes) → payload_hash  [separate from CID]
    ├─ Step 4: invoke_chaincode(event_id, payload_hash, ipfs_cid,
    │          timestamp, severity, attack_category, detection_confidence,
    │          model_version, agent_identity, agent_signature, cloud_asset_id)
    └─ Step 5+6: Verify ledger record + cross-validate vs IPFS
           │
           ▼
  Hyperledger Fabric 2.5  (single-org: Org1, Raft consensus, CouchDB state DB)
    └─ chaincode/security_logger.go
         ├─ LogSecurityEvent()       ← 11-arg write (Org1MSP only)
         ├─ VerifyEvent()            ← integrity check
         ├─ QueryEventHistory()      ← asset + time-window audit trail
         └─ QueryEventsBySeverity()  ← compliance reporting
    └─ CouchDB (indexed on cloud_asset_id+timestamp, severity+timestamp)

  IPFS node  (kubo:v0.28.0)
    └─ Encrypted full event payloads
       On-chain: SHA-256 hash + CID + metadata only  (≤ 1 KB/event)

  audit_query.py   ← CLI + library
    ├─ get_event_history()       → time-window asset audit trail
    ├─ get_events_by_severity()  → compliance report by severity
    ├─ verify_ipfs_integrity()   → rehash IPFS bytes vs on-chain hash
    └─ export_report()           → JSON / CSV (ISO 27001, SOC 2, NIST SP 800-92)
```

---

## Repository Structure

| Path | Status | Description |
|---|---|---|
| `chaincode/security_logger.go` | ✅ Production | 11-arg LogSecurityEvent, VerifyEvent, QueryEventHistory, QueryEventsBySeverity |
| `chaincode/META-INF/statedb/couchdb/indexes/` | ✅ Production | CouchDB indexes for asset+timestamp, severity+timestamp |
| `live_blockchain_logger.py` | ✅ Production | Full pipeline — sign, encrypt, IPFS, 11-arg Fabric invoke |
| `audit_query.py` | ✅ Production | Audit trail CLI + compliance export; schema validation |
| `pki_signer.py` | ✅ Production | ECDSA P-256 signing + X.509 non-repudiation |
| `ipfs_uploader.py` | ✅ Production | IPFS upload helper with fallback |
| `docker-compose.yml` | ✅ Production | Fabric CA, Orderer, 2× Peers, 2× CouchDB, IPFS |
| `kubernetes/fabric-deployment.yaml` | ✅ Production | K8s manifests + HPA |
| `configtx.yaml` | ✅ Production | Single-org Raft channel configuration |
| `scripts/enroll_agent.sh` | ✅ Production | Fabric CA agent enrolment → X.509 credentials |
| `benchmark.py` | ✅ Production | KPI evidence: TPS, latency, storage, integrity, custody |
| `test_e2e.py` | ✅ Production | Automated end-to-end test suite (10 tests) |
| `mock_blockchain_logger.py` | ⚠️ Mock only | Simulation prototype — NOT evidence, NOT production |
| `results/` | Evidence | Benchmark outputs committed here for thesis appendix |

---

## Quick Start (single-org network)

### 1. Fabric binaries

```bash
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.0
export PATH=$PATH:$(pwd)/fabric-samples/bin
```

### 2. Crypto + genesis block

```bash
cryptogen generate --config=./crypto-config.yaml
mkdir -p channel-artifacts
configtxgen -profile TwoOrgsOrdererGenesis -channelID system-channel \
            -outputBlock channel-artifacts/genesis.block
configtxgen -profile TwoOrgsChannel -channelID mychannel \
            -outputCreateChannelTx channel-artifacts/mychannel.tx
```

### 3. Start network

```bash
docker compose up -d
./deploy_network_and_cc.sh
```

### 4. Enrol detection agent

```bash
bash scripts/enroll_agent.sh
```

### 5. Python dependencies

```bash
pip install pycryptodome requests cryptography
```

### 6. Run end-to-end tests

```bash
python test_e2e.py
```

### 7. Run the live logger (single event)

```bash
python live_blockchain_logger.py
```

### 8. Benchmark (evidence for KPIs)

```bash
python benchmark.py --events 200 --asset vm-prod-01
# Results written to results/benchmark_results_<timestamp>.json
```

### 9. Compliance report

```bash
# All events for an asset (last 30 days)
python audit_query.py --asset vm-prod-01 --from 2025-01-01 --format csv --output results/report.csv

# All CRITICAL events
python audit_query.py --severity CRITICAL --format json

# Single event + IPFS integrity check
python audit_query.py --event-id evt_abc123 --verify-ipfs
```

---

## Removing the Committed `secret.key` from Git History

The `secret.key` file was committed in an earlier version and **must be purged** from history.
The key it contained is **compromised** — rotate it immediately.

```bash
# Remove from working tree and index
git rm --cached secret.key
rm -f secret.key
git commit -m "Remove committed secret key"

# Purge from all history (requires git-filter-repo)
pip install git-filter-repo
git filter-repo --path secret.key --invert-paths
git push --force --all
git push --force --tags
```

---

## Objective 2 KPI Evidence Map

| # | KPI | Target | Evidence source |
|---|---|---|---|
| 1 | Transaction Throughput | ≥ 1,000 TPS | `benchmark.py` → `results/benchmark_results_*.json` |
| 2 | Log Commit Latency | ≤ 500 ms (p95) | `benchmark.py` → latency percentiles |
| 3 | On-Chain Storage | ≤ 1 KB/event | `benchmark.py:measure_on_chain_storage()` |
| 4 | Integrity Failure Rate | 0% | `benchmark.py:run_integrity_verification_test()` |
| 5 | Smart Contract Audit | Zero critical vulns | Run `gosec ./chaincode/...` externally |
| 6 | Forensic Chain-of-Custody | Unbroken trace | `benchmark.py:run_chain_of_custody_report()` |

---

## Security Notes

- `secret.key` is **compromised** — rotate immediately and purge from git history (see above).
- AES key is stored in `.aes_key` (gitignored) at runtime, never in a tracked file.
- Agent X.509 credentials live in `crypto-config/` (gitignored), issued by Fabric CA.
- All production code is in `live_blockchain_logger.py`. The mock (`mock_blockchain_logger.py`) must not be cited as evidence.
