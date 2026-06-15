# Operational Runbook

## Quick Start

```bash
make up          # Start all services
make health      # Verify all healthy
make topics      # Create Kafka topics (if not already created)
```

## Daily Operations

### Check Consumer Lag
```bash
bash messaging/kafka-consumer-groups.sh
```
If lag for `blockchain-logger-group` exceeds 5,000 messages, scale up the blockchain-logger:
```bash
kubectl scale deployment blockchain-logger --replicas=8 -n fabric-security
```

### View Service Logs
```bash
docker-compose logs -f blockchain-logger  # Follow logger logs
docker-compose logs --tail=100 audit-api  # Last 100 audit-api lines
```

### Run Integrity Check
```bash
curl -X POST http://localhost:8001/api/v1/audit/event/{event_id}
# Verify chain_sha256 == ipfs_sha256 in response
```

## Alert Responses

### `HighEventIngestionFailureRate`
1. Check DLQ topic for dead-lettered events: `kafka-console-consumer --topic security-events-dlq --bootstrap-server localhost:9092 --from-beginning`
2. Check detector-adapter logs for errors: `docker-compose logs detector-adapter`
3. Verify Kafka broker health

### `BlockchainLoggerConsumerLag`
1. Check logger worker threads: `docker-compose logs blockchain-logger`
2. Verify Fabric peer connectivity
3. Scale up workers: increase `WORKER_THREADS` env var and restart

### `FabricSubmissionFailures`
1. Check Fabric peer health: `peer node status`
2. Verify TLS certificates are not expired
3. Check orderer availability

## Compliance Report Generation

On-demand:
```bash
curl -X POST http://localhost:8001/api/v1/compliance/report \
  -H 'Content-Type: application/json' \
  -d '{"standard":"ISO-27001","start_time":"2025-01-01T00:00:00Z","end_time":"2025-12-31T23:59:59Z","output_format":"json"}'
```

Scheduled reports are written to `/app/reports/` by the compliance-scheduler.
