#!/usr/bin/env bash
# Configure Kafka ACLs for service principals
set -euo pipefail

BOOTSTRAP="${KAFKA_BOOTSTRAP_SERVERS:-localhost:9092}"

apply_acl() {
  kafka-acls.sh --bootstrap-server "$BOOTSTRAP" "$@"
}

# detector-adapter: produce to security-events
apply_acl --add --allow-principal User:detector-adapter \
  --operation Write --topic security-events

# blockchain-logger: consume from security-events
apply_acl --add --allow-principal User:blockchain-logger \
  --operation Read --topic security-events \
  --group blockchain-logger-group

# All services: read DLQ
apply_acl --add --allow-principal User:* \
  --operation Read --topic security-events-dlq

echo "[kafka-acls] ACLs applied."
