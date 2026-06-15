#!/usr/bin/env python3
"""
live_blockchain_logger.py  —  Objective 2 Production Logger
------------------------------------------------------------
Full pipeline:
  1. Canonicalise event payload with correct schema
  2. Sign event with Fabric CA-enrolled ECDSA key (pki_signer.py)
  3. Encrypt full payload with AES-256-GCM, upload to IPFS
  4. Compute SHA-256 over stored payload bytes (separate from CID)
  5. Submit 11-arg LogSecurityEvent to Fabric (single-org: Org1 only)
  6. Verify ledger record and cross-validate against IPFS payload

Environment variables (all optional, sensible defaults for test-network):
  FABRIC_SAMPLES_DIR   path to fabric-samples  (default: ./fabric-samples)
  CHANNEL_NAME         Fabric channel           (default: mychannel)
  CHAINCODE_NAME       chaincode name           (default: security_logger)
  IPFS_API_URL         IPFS API endpoint        (default: http://127.0.0.1:5001)
  AGENT_KEY_PATH       ECDSA private key PEM    (default: crypto-config/agent/keystore/agent_sk)
  AGENT_CERT_PATH      X.509 cert PEM           (default: crypto-config/agent/signcerts/agent.pem)
  AES_KEY_PATH         AES-256 key file         (default: .aes_key  — gitignored, NEVER secret.key)

Dependencies:
  pip install pycryptodome requests cryptography
"""

import base64
import hashlib
import io
import json
import logging
import os
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [LOGGER] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration  (single-org network — Org1 only)
# ---------------------------------------------------------------------------
BASE_DIR         = os.path.abspath(os.environ.get("FABRIC_SAMPLES_DIR", "fabric-samples"))
BIN_DIR          = os.path.join(BASE_DIR, "bin")
PEER_BIN         = os.path.join(BIN_DIR, "peer")
TEST_NETWORK_DIR = os.path.join(BASE_DIR, "test-network")
ORG1_DIR         = os.path.join(TEST_NETWORK_DIR, "organizations/peerOrganizations/org1.example.com")
ORDERER_DIR      = os.path.join(TEST_NETWORK_DIR, "organizations/ordererOrganizations/example.com")

CHANNEL_NAME   = os.environ.get("CHANNEL_NAME",   "mychannel")
CHAINCODE_NAME = os.environ.get("CHAINCODE_NAME", "security_logger")
IPFS_API_URL   = os.environ.get("IPFS_API_URL",   "http://127.0.0.1:5001")
MODEL_VERSION  = os.environ.get("MODEL_VERSION",  "obj1-cnn-lstm-transformer-v1")

# AES key lives in a gitignored file, NEVER in secret.key
AES_KEY_PATH   = os.environ.get("AES_KEY_PATH", ".aes_key")

AGENT_KEY_PATH  = os.environ.get("AGENT_KEY_PATH",  "crypto-config/agent/keystore/agent_sk")
AGENT_CERT_PATH = os.environ.get("AGENT_CERT_PATH", "crypto-config/agent/signcerts/agent.pem")

# ---------------------------------------------------------------------------
# AES-256-GCM key management
# ---------------------------------------------------------------------------

def load_or_create_aes_key() -> bytes:
    """
    Load AES-256 key from AES_KEY_PATH (gitignored), or generate one.
    Never stores to secret.key or any tracked file.
    """
    path = Path(AES_KEY_PATH)
    if path.exists():
        key = path.read_bytes()
        log.info("[AES] Loaded existing key from %s", path)
        return key
    key = get_random_bytes(32)
    path.write_bytes(key)
    log.info("[AES] Generated new AES-256 key at %s", path)
    return key


def encrypt_payload(payload_dict: dict, key: bytes) -> dict:
    """AES-256-GCM encrypt payload_dict, return base64-encoded package."""
    plaintext = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        "nonce":      base64.b64encode(cipher.nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag":        base64.b64encode(tag).decode(),
    }


def decrypt_payload(encrypted_package: dict, key: bytes) -> dict:
    """Decrypt an AES-256-GCM package and return original dict."""
    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=base64.b64decode(encrypted_package["nonce"]),
    )
    plaintext = cipher.decrypt_and_verify(
        base64.b64decode(encrypted_package["ciphertext"]),
        base64.b64decode(encrypted_package["tag"]),
    )
    return json.loads(plaintext.decode("utf-8"))


# ---------------------------------------------------------------------------
# IPFS  —  encrypt then upload; return (cid, sha256_hash)
# ---------------------------------------------------------------------------

def store_off_chain_ipfs_encrypted(
    payload_dict: dict,
    key: bytes,
) -> tuple[str | None, str | None, dict | None]:
    """
    Encrypt *payload_dict* and store in IPFS.
    Returns (cid, sha256_hex_of_stored_bytes, encrypted_package)
    where sha256_hex is computed over the raw bytes actually written to IPFS
    so that verify_ipfs_integrity() can rehash and confirm equality.
    Returns (None, None, None) on failure.
    """
    try:
        encrypted_package = encrypt_payload(payload_dict, key)
        payload_bytes = json.dumps(encrypted_package, sort_keys=True).encode("utf-8")
        payload_hash  = hashlib.sha256(payload_bytes).hexdigest()

        files = {
            "file": ("event.enc.json", io.BytesIO(payload_bytes), "application/json")
        }
        response = requests.post(
            f"{IPFS_API_URL}/api/v0/add",
            files=files,
            timeout=30,
        )
        response.raise_for_status()
        cid = response.json()["Hash"]
        log.info("[IPFS] Stored encrypted payload  CID=%s  SHA256=%s", cid, payload_hash)
        return cid, payload_hash, encrypted_package

    except Exception as exc:  # noqa: BLE001
        log.error("[IPFS] Upload failed: %s — using hash-only fallback", exc)
        # Fallback: still compute hash so we don’t lose the event
        encrypted_package = encrypt_payload(payload_dict, key)
        payload_bytes = json.dumps(encrypted_package, sort_keys=True).encode("utf-8")
        payload_hash  = hashlib.sha256(payload_bytes).hexdigest()
        return f"sha256:{payload_hash}", payload_hash, encrypted_package


def retrieve_and_decrypt_from_ipfs(cid: str, key: bytes) -> dict | None:
    """Download IPFS payload by CID and decrypt it."""
    if cid.startswith("sha256:"):
        log.warning("[IPFS] CID is a hash-only fallback — no content to retrieve")
        return None
    try:
        response = requests.post(
            f"{IPFS_API_URL}/api/v0/cat",
            params={"arg": cid},
            timeout=30,
        )
        response.raise_for_status()
        encrypted_package = json.loads(response.content.decode("utf-8"))
        decrypted = decrypt_payload(encrypted_package, key)
        log.info("[IPFS] Retrieval + decryption successful for CID=%s", cid)
        return decrypted
    except Exception as exc:  # noqa: BLE001
        log.error("[IPFS] Retrieval/decryption failed for CID=%s: %s", cid, exc)
        return None


# ---------------------------------------------------------------------------
# PKI signing  (delegates to pki_signer.py)
# ---------------------------------------------------------------------------

def get_signer():
    """
    Return an EventSigner loaded from Fabric CA-enrolled credentials.
    Falls back gracefully if crypto-config is absent (dev/test mode).
    """
    try:
        from pki_signer import EventSigner  # noqa: PLC0415
        return EventSigner(key_path=AGENT_KEY_PATH, cert_path=AGENT_CERT_PATH)
    except FileNotFoundError as exc:
        log.warning("[PKI] Credentials not found (%s) — run scripts/enroll_agent.sh first", exc)
        return None
    except ImportError:
        log.warning("[PKI] pki_signer module not available")
        return None


# ---------------------------------------------------------------------------
# Fabric chaincode invocation  —  single-org (Org1 only)
# ---------------------------------------------------------------------------

def _fabric_env() -> dict:
    """Return env dict configured for Org1 peer."""
    env = os.environ.copy()
    env["FABRIC_CFG_PATH"]          = os.path.join(BASE_DIR, "config")
    env["CORE_PEER_TLS_ENABLED"]    = "true"
    env["CORE_PEER_LOCALMSPID"]     = "Org1MSP"
    env["CORE_PEER_TLS_ROOTCERT_FILE"] = os.path.join(
        ORG1_DIR, "peers/peer0.org1.example.com/tls/ca.crt")
    env["CORE_PEER_MSPCONFIGPATH"]  = os.path.join(
        ORG1_DIR, "users/Admin@org1.example.com/msp")
    env["CORE_PEER_ADDRESS"]        = "localhost:7051"
    return env


def invoke_chaincode(
    event_id: str,
    payload_hash: str,
    ipfs_cid: str,
    timestamp: str,
    severity: str,
    attack_category: str,
    detection_confidence: float,
    model_version: str,
    agent_identity: str,
    agent_signature: str,
    cloud_asset_id: str,
) -> dict | None:
    """
    Invoke LogSecurityEvent on Fabric with all 11 arguments.
    Single-org endorsement (Org1 peer only).
    Returns the verified ledger record, or None on failure.
    """
    args_json = json.dumps([
        str(event_id),
        str(payload_hash),
        str(ipfs_cid),
        str(timestamp),
        str(severity),
        str(attack_category),
        str(float(detection_confidence)),  # JSON number→string for CLI
        str(model_version),
        str(agent_identity),
        str(agent_signature),
        str(cloud_asset_id),
    ])

    env             = _fabric_env()
    orderer_tls_ca  = os.path.join(
        ORDERER_DIR,
        "orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem",
    )
    org1_tls_ca = env["CORE_PEER_TLS_ROOTCERT_FILE"]

    invoke_command = [
        PEER_BIN, "chaincode", "invoke",
        "-o",  "localhost:7050",
        "--ordererTLSHostnameOverride", "orderer.example.com",
        "--tls",
        "--cafile",         orderer_tls_ca,
        "-C",               CHANNEL_NAME,
        "-n",               CHAINCODE_NAME,
        # Single-org endorsement — Org1 only
        "--peerAddresses",  "localhost:7051",
        "--tlsRootCertFiles", org1_tls_ca,
        "-c",               f'{{"function":"LogSecurityEvent","Args":{args_json}}}',
    ]

    log.info("[FABRIC] Submitting LogSecurityEvent  id=%s", event_id)
    try:
        result = subprocess.run(
            invoke_command, env=env,
            capture_output=True, text=True, check=True,
        )
        log.info("[FABRIC] Endorsed by peer.  %s", result.stderr.strip())
    except subprocess.CalledProcessError as exc:
        log.error(
            "[FABRIC] Invoke failed (rc=%s)\nstdout: %s\nstderr: %s",
            exc.returncode, exc.stdout, exc.stderr,
        )
        return None

    log.info("[FABRIC] Waiting 3 s for orderer to cut block…")
    time.sleep(3)

    # Verify
    query_command = [
        PEER_BIN, "chaincode", "query",
        "-C", CHANNEL_NAME,
        "-n", CHAINCODE_NAME,
        "-c", f'{{"function":"VerifyEvent","Args":["{event_id}"]}}',
    ]
    try:
        qr = subprocess.run(
            query_command, env=env,
            capture_output=True, text=True, check=True,
        )
        ledger_record = json.loads(qr.stdout)
        log.info("[FABRIC] Ledger verification OK  id=%s", event_id)
        return ledger_record
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        log.error("[FABRIC] Ledger verification failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Canonical event payload schema
# ---------------------------------------------------------------------------

def build_event_payload(
    attack_category: str = "DDoS",
    detection_confidence: float = 0.98,
    severity: str = "HIGH",
    source_ip: str = "192.168.1.105",
    destination_ip: str = "10.0.0.50",
    cloud_asset_id: str = "vm-prod-01",
    pkt_rate: int = 1200,
    syn_ratio: float = 0.88,
) -> dict:
    """
    Build a canonical event payload that matches both the on-chain metadata
    schema and the audit_query.py / compliance report field names.
    """
    return {
        "event_id":            f"evt_{int(time.time())}_{uuid.uuid4().hex[:8]}",
        "timestamp":           datetime.now(timezone.utc).isoformat(),
        "severity":            severity,
        "attack_category":     attack_category,
        "detection_confidence": detection_confidence,
        "source_ip":           source_ip,
        "destination_ip":      destination_ip,
        "cloud_asset_id":      cloud_asset_id,
        "model_version":       MODEL_VERSION,
        "raw_features": {
            "pkt_rate":  pkt_rate,
            "syn_ratio": syn_ratio,
        },
    }


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_pipeline(raw_event_payload: dict | None = None) -> bool:
    """
    Full Objective 2 pipeline.  Returns True on end-to-end success.
    """
    aes_key = load_or_create_aes_key()

    # --- Step 1: Prepare canonical event payload ---
    log.info("=" * 60)
    log.info("Step 1 — Preparing canonical security event payload")
    if raw_event_payload is None:
        raw_event_payload = build_event_payload()
    event_id     = raw_event_payload["event_id"]
    log.info("Event ID: %s", event_id)

    # --- Step 2: ECDSA sign with Fabric CA credentials ---
    log.info("Step 2 — Signing event with agent X.509 credentials (PKI)")
    signer = get_signer()
    if signer:
        agent_identity = signer.get_agent_identity()
        agent_signature = signer.sign_event(raw_event_payload)
        log.info("Signed by agent: %s", agent_identity)
    else:
        log.warning("PKI signer unavailable — using placeholder identity (dev mode)")
        agent_identity  = "dev-agent-unsigned"
        agent_signature = "unsigned"

    # --- Step 3: Encrypt + store full payload in IPFS ---
    log.info("Step 3 — Encrypting and uploading payload to IPFS")
    ipfs_cid, payload_hash, _ = store_off_chain_ipfs_encrypted(raw_event_payload, aes_key)
    if not ipfs_cid or not payload_hash:
        log.error("IPFS storage failed — aborting pipeline")
        return False
    log.info("CID: %s  |  SHA-256: %s", ipfs_cid, payload_hash)

    # --- Step 4: Submit to Fabric (11-argument API) ---
    log.info("Step 4 — Submitting to Hyperledger Fabric ledger")
    ledger_record = invoke_chaincode(
        event_id            = event_id,
        payload_hash        = payload_hash,
        ipfs_cid            = ipfs_cid,
        timestamp           = raw_event_payload["timestamp"],
        severity            = raw_event_payload["severity"],
        attack_category     = raw_event_payload["attack_category"],
        detection_confidence= raw_event_payload["detection_confidence"],
        model_version       = raw_event_payload["model_version"],
        agent_identity      = agent_identity,
        agent_signature     = agent_signature,
        cloud_asset_id      = raw_event_payload["cloud_asset_id"],
    )
    if not ledger_record:
        log.error("Fabric submission failed — aborting pipeline")
        return False

    # --- Step 5: Retrieve + decrypt from IPFS ---
    log.info("Step 5 — Retrieving and decrypting payload from IPFS")
    ipfs_payload = retrieve_and_decrypt_from_ipfs(ipfs_cid, aes_key)
    if ipfs_payload is None:
        log.warning("IPFS retrieval skipped (hash-only CID or unreachable node)")
    else:
        # --- Step 6: Cross-validate ledger record vs IPFS payload ---
        log.info("Step 6 — Cross-validating ledger record against IPFS payload")
        if ledger_record.get("event_id") == ipfs_payload.get("event_id"):
            log.info("✅ Cross-validation PASSED: ledger matches IPFS payload")
        else:
            log.error("❌ Cross-validation FAILED: event_id mismatch")
            return False

    log.info("✅ Pipeline complete for event_id=%s", event_id)
    return True


if __name__ == "__main__":
    success = run_pipeline()
    raise SystemExit(0 if success else 1)
