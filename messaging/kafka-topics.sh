#!/bin/bash
# Create Kafka topics for the security event pipeline
set -euo pipefail

BROKER="${KAFKA_BROKER:-localhost:9092}"

echo "Creating Kafka topics on broker: $BROKER"

kafka-topics.sh --bootstrap-server "$BROKER" --create --if-not-exists \
  --topic security-events \
  --partitions 12 \
  --replication-factor 3 \
  --config retention.ms=604800000 \
  --config min.insync.replicas=2 \
  --config compression.type=gzip

kafka-topics.sh --bootstrap-server "$BROKER" --create --if-not-exists \
  --topic security-events-dlq \
  --partitions 3 \
  --replication-factor 3 \
  --config retention.ms=2592000000 \
  --config min.insync.replicas=2

kafka-topics.sh --bootstrap-server "$BROKER" --create --if-not-exists \
  --topic security-events-audit \
  --partitions 6 \
  --replication-factor 3 \
  --config retention.ms=31536000000 \
  --config min.insync.replicas=2

echo "Topics created:"
kafka-topics.sh --bootstrap-server "$BROKER" --list
