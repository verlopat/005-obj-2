#!/usr/bin/env bash
# Tear down the dev stack and clean generated artifacts
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
echo "Destroying 005-obj-2 dev stack..."

docker compose -f "${BASE_DIR}/docker-compose.yml" down -v --remove-orphans 2>/dev/null || true

rm -rf \
  "${BASE_DIR}/crypto-config" \
  "${BASE_DIR}/genesis.block" \
  "${BASE_DIR}/channel.tx" \
  "${BASE_DIR}/results/"

echo "Stack destroyed and artifacts removed."
