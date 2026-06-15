#!/usr/bin/env bash
# scripts/enroll_agent.sh
# Enrol a detection agent with Hyperledger Fabric CA and generate X.509 credentials.
# Run this ONCE per detection agent before starting blockchain_logger.py.
#
# Prerequisites:
#   - fabric-ca-client binary in PATH
#   - Fabric CA server running (ca.org1.example.com:7054)
#   - Admin credentials: admin / adminpw
#
# Output:
#   crypto-config/agent/keystore/agent_sk
#   crypto-config/agent/signcerts/agent.pem

set -euo pipefail

CA_URL="${CA_URL:-http://localhost:7054}"
AGENT_NAME="${AGENT_NAME:-detection-agent-01}"
AGENT_PASS="${AGENT_PASS:-agentpw}"
MSP_DIR="./crypto-config/agent"

echo "[PKI] Enrolling admin to obtain CA TLS cert ..."
export FABRIC_CA_CLIENT_HOME="/tmp/fabric-ca-admin"
fabric-ca-client enroll \
  -u "${CA_URL}/admin:adminpw" \
  --tls.certfiles "$(pwd)/crypto-config/ca/ca.org1.example.com-cert.pem" \
  2>/dev/null || true  # may already be enrolled

echo "[PKI] Registering detection agent: ${AGENT_NAME} ..."
fabric-ca-client register \
  --id.name   "${AGENT_NAME}" \
  --id.secret "${AGENT_PASS}" \
  --id.type   client \
  --id.affiliation org1.department1 \
  --tls.certfiles "$(pwd)/crypto-config/ca/ca.org1.example.com-cert.pem" \
  2>/dev/null || echo "[PKI] Agent already registered, skipping."

echo "[PKI] Enrolling detection agent: ${AGENT_NAME} ..."
mkdir -p "${MSP_DIR}"
export FABRIC_CA_CLIENT_HOME="${MSP_DIR}"
fabric-ca-client enroll \
  -u "${CA_URL}/${AGENT_NAME}:${AGENT_PASS}" \
  --tls.certfiles "$(pwd)/crypto-config/ca/ca.org1.example.com-cert.pem"

KEYSTORE_DIR="${MSP_DIR}/msp/keystore"
SIGNCERTS_DIR="${MSP_DIR}/msp/signcerts"

# Normalise paths expected by pki_signer.py
mkdir -p "${MSP_DIR}/keystore" "${MSP_DIR}/signcerts"
cp "${KEYSTORE_DIR}/"*_sk "${MSP_DIR}/keystore/agent_sk"
cp "${SIGNCERTS_DIR}/"*.pem "${MSP_DIR}/signcerts/agent.pem"

echo "[PKI] Agent credentials written to:"
echo "      Key : ${MSP_DIR}/keystore/agent_sk"
echo "      Cert: ${MSP_DIR}/signcerts/agent.pem"
echo "[PKI] Done. You can now run blockchain_logger.py."
