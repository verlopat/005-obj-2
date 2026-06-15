#!/bin/bash
# Check health of all services
set -euo pipefail
OK="\033[0;32m✔\033[0m"
FAIL="\033[0;31m✘\033[0m"

check() {
  local name=$1 url=$2
  if curl -sf "$url" > /dev/null 2>&1; then
    echo -e "$OK $name"
  else
    echo -e "$FAIL $name ($url)"
  fi
}

echo "=== Service Health Check ==="
check "Detector Adapter" "http://localhost:8000/healthz"
check "Audit API"         "http://localhost:8001/healthz"
check "Prometheus"        "http://localhost:9090/-/healthy"
check "Grafana"           "http://localhost:3000/api/health"
check "IPFS API"          "http://localhost:5001/api/v0/version"
