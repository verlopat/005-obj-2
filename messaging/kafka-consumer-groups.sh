#!/bin/bash
# Describe consumer groups for lag monitoring
set -euo pipefail
BROKER="${KAFKA_BROKER:-localhost:9092}"
echo "=== blockchain-logger-group ==="
kafka-consumer-groups.sh --bootstrap-server "$BROKER" \
  --describe --group blockchain-logger-group
echo "=== All groups ==="
kafka-consumer-groups.sh --bootstrap-server "$BROKER" --list
