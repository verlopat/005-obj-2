#!/bin/bash
# Bootstrap the full Fabric + IPFS + Kafka stack
set -euo pipefail

log() { echo -e "\033[0;32m[BOOTSTRAP]\033[0m $*"; }
error() { echo -e "\033[0;31m[ERROR]\033[0m $*" >&2; exit 1; }

log "Checking prerequisites..."
for cmd in docker docker-compose curl; do
  command -v $cmd >/dev/null 2>&1 || error "$cmd not found"
done

log "Generating crypto materials..."
if command -v cryptogen >/dev/null 2>&1; then
  cryptogen generate --config=./crypto-config.yaml
else
  log "cryptogen not found — skipping (use fabric-ca enrolment instead)"
fi

log "Generating genesis block..."
if command -v configtxgen >/dev/null 2>&1; then
  configtxgen -profile TwoOrgsOrdererGenesis -channelID system-channel -outputBlock ./channel-artifacts/genesis.block
  configtxgen -profile TwoOrgsChannel -outputCreateChannelTx ./channel-artifacts/security-channel.tx -channelID security-channel
else
  log "configtxgen not found — skipping"
fi

log "Starting Docker Compose stack..."
mkdir -p channel-artifacts
docker-compose up -d --build

log "Waiting for services to be healthy (30s)..."
sleep 30

log "Creating Kafka topics..."
bash messaging/kafka-topics.sh || log "Kafka topics may already exist"

log "Creating Fabric channel..."
if command -v peer >/dev/null 2>&1; then
  peer channel create -o localhost:7050 -c security-channel \
    -f ./channel-artifacts/security-channel.tx \
    --outputBlock ./channel-artifacts/security-channel.block \
    --tls --cafile /etc/hyperledger/fabric/tls/ca.crt
  peer channel join -b ./channel-artifacts/security-channel.block
else
  log "peer CLI not found — skipping channel creation"
fi

log "Bootstrap complete! Stack is ready."
log "  Detector Adapter:   http://localhost:8000"
log "  Audit API:          http://localhost:8001"
log "  Prometheus:         http://localhost:9090"
log "  Grafana:            http://localhost:3000"
log "  IPFS Gateway:       http://localhost:8080"
