/**
 * k6 load test for the security event pipeline.
 * Usage: k6 run --vus 50 --duration 60s k6-load-test.js
 */
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Histogram, Rate } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';

export const options = {
  scenarios: {
    ramp_up: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '30s', target: 20 },
        { duration: '60s', target: 50 },
        { duration: '30s', target: 100 },
        { duration: '30s', target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],
    http_req_failed: ['rate<0.01'],
  },
};

const eventProduced = new Counter('events_produced');
const failedEvents = new Counter('events_failed');
const ingestLatency = new Histogram('ingest_latency_ms');
const successRate = new Rate('success_rate');

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const CATEGORIES = ['DDOS', 'INTRUSION', 'DATA_EXFILTRATION', 'ANOMALY'];

function randomEvent() {
  return JSON.stringify({
    asset_id: `asset-${Math.floor(Math.random() * 100)}`,
    cloud_provider: 'AWS',
    region: 'us-east-1',
    severity: SEVERITIES[Math.floor(Math.random() * SEVERITIES.length)],
    attack_category: CATEGORIES[Math.floor(Math.random() * CATEGORIES.length)],
    description: `k6 load test event ${Date.now()}`,
    detection_confidence: 0.95,
    model_version: 'v1.0',
  });
}

export default function () {
  const headers = { 'Content-Type': 'application/json' };
  const start = Date.now();
  const res = http.post(`${BASE_URL}/api/v1/events`, randomEvent(), { headers });
  ingestLatency.add(Date.now() - start);

  const ok = check(res, {
    'status is 202': (r) => r.status === 202,
    'has event_id': (r) => r.json('event_id') !== null,
  });

  if (ok) {
    eventProduced.add(1);
    successRate.add(1);
  } else {
    failedEvents.add(1);
    successRate.add(0);
  }

  sleep(Math.random() * 0.3);
}
