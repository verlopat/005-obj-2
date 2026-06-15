#!/bin/bash
# Tear down the full stack and clean up volumes
set -euo pipefail
log() { echo -e "\033[0;33m[DESTROY]\033[0m $*"; }
log "Stopping all services..."
docker-compose down -v --remove-orphans 2>/dev/null || true
log "Removing generated crypto materials..."
rm -rf crypto-config/ channel-artifacts/ reports/
log "Removing dangling volumes..."
docker volume prune -f
log "Stack destroyed."
