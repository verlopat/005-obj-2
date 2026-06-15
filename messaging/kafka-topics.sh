#!/usr/bin/env bash
# Create all required Kafka topics for the security logging pipeline
set -euo pipefail

KAFKA_BROKER="${KAFKA_BROKER:-localhost:9092}"
REPLICATION="${KAFKA_REPLICATION_FACTOR:-1}"

echo "Creating Kafka topics on ${KAFKA_BROKER}..."

create_topic() {
  local topic="$1" partitions="$2" retention_ms="$3"
  kafka-topics.sh --bootstrap-server "${KAFKA_BROKER}" \
    --create --if-not-exists \
    --topic "${topic}" \
    --partitions "${partitions}" \
    --replication-factor "${REPLICATION}" \
    --config retention.ms="${retention_ms}" \
    --config min.insync.replicas=1 \
    --config cleanup.policy=delete
  echo "  ✓ ${topic} (partitions=${partitions}, retention=${retention_ms}ms)"
}

# Primary event stream: 12 partitions for parallel consumption
create_topic "security-events"     12  604800000   # 7 days
create_topic "security-events-dlq"  3  2592000000  # 30 days
create_topic "audit-queries"        4  86400000    # 1 day
create_topic "compliance-reports"   2  2592000000  # 30 days

echo "All topics created."
kafka-topics.sh --bootstrap-server "${KAFKA_BROKER}" --list
