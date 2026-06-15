import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

export let errorRate = new Rate('errors');
export let logLatency = new Trend('blockchain_log_latency_ms', true);

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const CATEGORIES = ['DDOS', 'INTRUSION', 'DATA_EXFILTRATION', 'ANOMALY'];

export let options = {
  stages: [
    { duration: '1m',  target: 50  },
    { duration: '3m',  target: 200 },
    { duration: '5m',  target: 500 },
    { duration: '5m',  target: 500 },
    { duration: '2m',  target: 100 },
    { duration: '1m',  target: 0   },
  ],
  thresholds: {
    'http_req_duration': ['p(95)<500', 'p(99)<1000'],
    'errors':            ['rate<0.01'],
    'http_req_failed':   ['rate<0.01'],
  },
};

function generateEvent() {
  return {
    asset_id: `asset-${Math.floor(Math.random() * 500)}`,
    cloud_provider: ['AWS', 'GCP', 'Azure'][Math.floor(Math.random() * 3)],
    region: 'us-east-1',
    severity: SEVERITIES[Math.floor(Math.random() * SEVERITIES.length)],
    attack_category: CATEGORIES[Math.floor(Math.random() * CATEGORIES.length)],
    description: `k6 load test event ${Date.now()}`,
    source_ip: `10.0.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*254)+1}`,
    detection_confidence: 0.85 + Math.random() * 0.15,
    model_version: 'v1.0',
  };
}

export default function () {
  const start = Date.now();
  const res = http.post(
    `${BASE_URL}/api/v1/events`,
    JSON.stringify(generateEvent()),
    { headers: { 'Content-Type': 'application/json' } },
  );
  logLatency.add(Date.now() - start);
  const ok = check(res, {
    'status 202': (r) => r.status === 202,
    'has event_id': (r) => r.json('event_id') !== null,
  });
  errorRate.add(!ok);
  sleep(0.1);
}
