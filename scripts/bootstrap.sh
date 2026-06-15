#!/usr/bin/env bash
# Bootstrap the full security logging stack (dev environment)
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
echo "Bootstrapping 005-obj-2 from ${BASE_DIR}"

# 1. Generate crypto material
if command -v cryptogen &> /dev/null; then
  echo "[1/6] Generating crypto material..."
  cryptogen generate --config="${BASE_DIR}/configtx.yaml" --output="${BASE_DIR}/crypto-config"
else
  echo "[1/6] cryptogen not found - skipping (use fabric-ca in production)"
fi

# 2. Generate genesis block
if command -v configtxgen &> /dev/null; then
  echo "[2/6] Generating genesis block..."
  configtxgen -profile SecurityOrdererGenesis -channelID system-channel \
    -outputBlock "${BASE_DIR}/genesis.block"
  configtxgen -profile SecurityChannel -outputCreateChannelTx \
    "${BASE_DIR}/channel.tx" -channelID security-channel
else
  echo "[2/6] configtxgen not found - skipping"
fi

# 3. Start docker compose stack
echo "[3/6] Starting Docker Compose stack..."
docker compose -f "${BASE_DIR}/docker-compose.yml" up -d

# 4. Wait for services
echo "[4/6] Waiting for services to be healthy..."
sleep 15

# 5. Create Kafka topics
echo "[5/6] Creating Kafka topics..."
bash "${BASE_DIR}/messaging/kafka-topics.sh"

# 6. Enrol Fabric agent
echo "[6/6] Enrolling detection agent identity..."
bash "${BASE_DIR}/scripts/enroll_agent.sh"

echo ""
echo "Bootstrap complete!"
echo "  Detector adapter: http://localhost:8000"
echo "  Audit API:        http://localhost:8001"
echo "  Prometheus:       http://localhost:9090"
echo "  Grafana:          http://localhost:3000 (admin/admin)"
