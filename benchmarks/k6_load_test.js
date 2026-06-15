/**
 * k6 load test for the detector-adapter and audit-api.
 * Run: k6 run benchmarks/k6_load_test.js
 */
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Trend } from 'k6/metrics';

const eventsFailed  = new Counter('events_failed');
const ingestLatency = new Trend('ingest_latency_ms', true);

export const options = {
  stages: [
    { duration: '30s', target: 50  },
    { duration: '2m',  target: 200 },
    { duration: '1m',  target: 500 },
    { duration: '30s', target: 0   },
  ],
  thresholds: {
    'http_req_failed':    ['rate<0.01'],
    'http_req_duration':  ['p(95)<500'],
    'ingest_latency_ms':  ['p(99)<1000'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const CATEGORIES = ['DDOS', 'INTRUSION', 'DATA_EXFILTRATION', 'ANOMALY'];

function makeEvent() {
  return {
    asset_id:             `vm-${Math.floor(Math.random() * 500).toString().padStart(4, '0')}`,
    cloud_provider:       ['AWS','GCP','AZURE'][Math.floor(Math.random()*3)],
    region:               'us-east-1',
    severity:             SEVERITIES[Math.floor(Math.random() * SEVERITIES.length)],
    attack_category:      CATEGORIES[Math.floor(Math.random() * CATEGORIES.length)],
    description:          `k6 load test event ${Date.now()}`,
    detection_confidence: Math.random().toFixed(3),
    model_version:        'v1.0',
    timestamp:            new Date().toISOString(),
  };
}

export default function () {
  const start = Date.now();
  const res = http.post(
    `${BASE_URL}/api/v1/events`,
    JSON.stringify(makeEvent()),
    { headers: { 'Content-Type': 'application/json' } },
  );
  ingestLatency.add(Date.now() - start);
  const ok = check(res, {
    'status is 202': r => r.status === 202,
    'has event_id':  r => !!JSON.parse(r.body).event_id,
  });
  if (!ok) eventsFailed.add(1);
  sleep(0.1);
}
