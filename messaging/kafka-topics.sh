#!/usr/bin/env bash
# Create all required Kafka topics for the security logging platform
set -euo pipefail

BOOTSTRAP="${KAFKA_BOOTSTRAP_SERVERS:-localhost:9092}"
PARTITIONS="${KAFKA_PARTITIONS:-6}"
REPLICAS="${KAFKA_REPLICAS:-3}"
RETENTION_MS="${KAFKA_RETENTION_MS:-604800000}"  # 7 days default

echo "[kafka-topics] Bootstrap: $BOOTSTRAP  Partitions: $PARTITIONS  Replicas: $REPLICAS"

create_topic() {
  local TOPIC=$1
  local EXTRA_OPTS=${2:-""}
  kafka-topics.sh \
    --bootstrap-server "$BOOTSTRAP" \
    --create \
    --if-not-exists \
    --topic "$TOPIC" \
    --partitions "$PARTITIONS" \
    --replication-factor "$REPLICAS" \
    --config retention.ms="$RETENTION_MS" \
    $EXTRA_OPTS
  echo "[kafka-topics]  Created/verified: $TOPIC"
}

# Primary events topic
create_topic "security-events" \
  "--config cleanup.policy=delete --config compression.type=gzip --config max.message.bytes=1048576"

# Dead-letter queue topic (longer retention for investigation)
create_topic "security-events-dlq" \
  "--config retention.ms=2592000000 --config cleanup.policy=delete"

# Compliance reports notification topic
create_topic "compliance-reports" \
  "--config cleanup.policy=delete"

# Audit trail events re-play topic (compacted)
create_topic "audit-trail-replay" \
  "--config cleanup.policy=compact --config min.cleanable.dirty.ratio=0.1"

echo "[kafka-topics] All topics ready."
