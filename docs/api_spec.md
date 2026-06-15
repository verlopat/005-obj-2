# API Specification

## Detector Adapter (Port 8000)

### POST /api/v1/events
Ingest a single security event.

**Request body:**
```json
{
  "asset_id": "aws-ec2-i-1234567890",
  "cloud_provider": "AWS",
  "region": "us-east-1",
  "severity": "HIGH",
  "attack_category": "DDOS",
  "description": "Volumetric DDoS detected: 45Gbps inbound traffic",
  "source_ip": "198.51.100.42",
  "detection_confidence": 0.97,
  "model_version": "v2.1"
}
```

**Response 202:**
```json
{"event_id": "550e8400-e29b-41d4-a716-446655440000", "status": "accepted"}
```

### POST /api/v1/events/batch
Ingest up to 100 events in a single request.

### GET /healthz
Health check. Returns `{"status": "ok", "kafka_connected": true}`.

---

## Audit API (Port 8001)

### POST /api/v1/audit/trail
Query event history for a specific cloud asset.

**Request body:**
```json
{"asset_id": "aws-ec2-i-1234", "start_time": "2025-01-01T00:00:00Z", "end_time": "2025-12-31T23:59:59Z", "page_size": 50}
```

### POST /api/v1/audit/severity
Query events by severity level with optional time filter.

### GET /api/v1/audit/event/{event_id}
Fetch a single immutable event record from the ledger.

### POST /api/v1/compliance/report
Generate a compliance report.

**Request body:**
```json
{"standard": "ISO-27001", "start_time": "2025-01-01T00:00:00Z", "end_time": "2025-12-31T23:59:59Z", "output_format": "json"}
```

Supported standards: `ISO-27001`, `SOC-2`, `NIST-SP-800-92`, `PCI-DSS`, `GDPR`.

### GET /healthz
Health check.
