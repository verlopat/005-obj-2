#!/usr/bin/env bash
# Check health of all running services
set -euo pipefail

DETECTOR_URL="${DETECTOR_URL:-http://localhost:8000}"
AUDIT_URL="${AUDIT_URL:-http://localhost:8001}"
PROMETHEUS_URL="${PROMETHEUS_URL:-http://localhost:9090}"

passed=0; failed=0

check() {
  local name="$1" url="$2" expected="$3"
  local status
  status=$(curl -sf -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null || echo "000")
  if [ "${status}" = "${expected}" ]; then
    echo "  ✓ ${name} (HTTP ${status})"
    ((passed++))
  else
    echo "  ✗ ${name} (expected HTTP ${expected}, got ${status})"
    ((failed++))
  fi
}

echo "=== Health Check ==="
check "Detector Adapter"  "${DETECTOR_URL}/healthz"                "200"
check "Audit API"          "${AUDIT_URL}/healthz"                   "200"
check "Prometheus"         "${PROMETHEUS_URL}/-/healthy"            "200"
check "Detector Metrics"   "${DETECTOR_URL}/metrics"               "200"
check "Audit Metrics"      "${AUDIT_URL}/metrics"                   "200"

echo ""
echo "Results: ${passed} passed, ${failed} failed"
[ "${failed}" -eq 0 ] && exit 0 || exit 1
