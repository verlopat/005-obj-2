import json
import time
import subprocess
import os
import uuid
import io
import requests
import base64

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- Path Configurations ---
BASE_DIR = os.path.abspath("fabric-samples")
BIN_DIR = os.path.join(BASE_DIR, "bin")
PEER_BIN = os.path.join(BIN_DIR, "peer")
TEST_NETWORK_DIR = os.path.join(BASE_DIR, "test-network")
ORG1_DIR = os.path.join(TEST_NETWORK_DIR, "organizations/peerOrganizations/org1.example.com")
ORDERER_DIR = os.path.join(TEST_NETWORK_DIR, "organizations/ordererOrganizations/example.com")

CHANNEL_NAME = "mychannel"
CHAINCODE_NAME = "security_logger"
KEY_FILE = "secret.key"

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = get_random_bytes(32)  # AES-256
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    print(f"[KEY] New AES-256 key generated and stored in {KEY_FILE}")
    return key

def encrypt_payload(payload_dict, key):
    plaintext = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    encrypted_package = {
        "nonce": base64.b64encode(cipher.nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8")
    }
    return encrypted_package

def decrypt_payload(encrypted_package, key):
    nonce = base64.b64decode(encrypted_package["nonce"])
    ciphertext = base64.b64decode(encrypted_package["ciphertext"])
    tag = base64.b64decode(encrypted_package["tag"])

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(plaintext.decode("utf-8"))

def store_off_chain_ipfs_encrypted(payload_dict, key):
    try:
        encrypted_package = encrypt_payload(payload_dict, key)
        payload_bytes = json.dumps(encrypted_package, sort_keys=True).encode("utf-8")

        files = {
            "file": ("event.enc.json", io.BytesIO(payload_bytes), "application/json")
        }
        response = requests.post(
            "http://127.0.0.1:5001/api/v0/add",
            files=files,
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
        cid = data["Hash"]
        print(f"[IPFS] Encrypted payload stored off-chain. CID: {cid}")
        return cid
    except Exception as e:
        print(f"IPFS Error during encrypted add: {e}")
        return None

def retrieve_and_decrypt_from_ipfs(cid, key):
    try:
        response = requests.post(
            f"http://127.0.0.1:5001/api/v0/cat?arg={cid}",
            timeout=30
        )
        response.raise_for_status()

        encrypted_package = json.loads(response.content.decode("utf-8"))
        decrypted_data = decrypt_payload(encrypted_package, key)
        print(f"✅ IPFS Retrieval + Decryption Successful! Payload:\n{json.dumps(decrypted_data, indent=2)}")
        return decrypted_data
    except Exception as e:
        print(f"IPFS Error during retrieval/decryption: {e}")
        return None

def invoke_chaincode(event_id, payload_hash, timestamp, severity, agent_id):
    args_json = json.dumps([
        str(event_id),
        str(payload_hash),
        str(timestamp),
        str(severity),
        str(agent_id)
    ])

    env = os.environ.copy()
    env["FABRIC_CFG_PATH"] = os.path.join(BASE_DIR, "config")
    env["CORE_PEER_TLS_ENABLED"] = "true"
    env["CORE_PEER_LOCALMSPID"] = "Org1MSP"
    env["CORE_PEER_TLS_ROOTCERT_FILE"] = os.path.join(
        ORG1_DIR,
        "peers/peer0.org1.example.com/tls/ca.crt"
    )
    env["CORE_PEER_MSPCONFIGPATH"] = os.path.join(
        ORG1_DIR,
        "users/Admin@org1.example.com/msp"
    )
    env["CORE_PEER_ADDRESS"] = "localhost:7051"

    orderer_tls_ca = os.path.join(
        ORDERER_DIR,
        "orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
    )
    org2_tls_ca = os.path.join(
        TEST_NETWORK_DIR,
        "organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
    )

    invoke_command = [
        PEER_BIN, "chaincode", "invoke",
        "-o", "localhost:7050",
        "--ordererTLSHostnameOverride", "orderer.example.com",
        "--tls",
        "--cafile", orderer_tls_ca,
        "-C", CHANNEL_NAME,
        "-n", CHAINCODE_NAME,
        "--peerAddresses", "localhost:7051",
        "--tlsRootCertFiles", env["CORE_PEER_TLS_ROOTCERT_FILE"],
        "--peerAddresses", "localhost:9051",
        "--tlsRootCertFiles", org2_tls_ca,
        "-c", f'{{"function":"LogSecurityEvent","Args":{args_json}}}'
    ]

    print("\n[Executing Native Host Transaction targeting Org1 and Org2...]")
    try:
        result = subprocess.run(
            invoke_command,
            env=env,
            capture_output=True,
            text=True,
            check=True
        )
        print(f"✅ Transaction successfully endorsed by peers!\n{result.stderr.strip()}")

        print("\n⏳ Waiting for the Orderer to cut a block and update the ledger (3 seconds)...")
        time.sleep(3)

        print("\n--- Step 4: Verifying from Ledger ---")
        query_command = [
            PEER_BIN, "chaincode", "query",
            "-C", CHANNEL_NAME,
            "-n", CHAINCODE_NAME,
            "-c", f'{{"function":"VerifyEvent","Args":["{event_id}"]}}'
        ]

        query_result = subprocess.run(
            query_command,
            env=env,
            capture_output=True,
            text=True,
            check=True
        )
        ledger_data = json.loads(query_result.stdout)
        print(f"✅ Ledger Verification Successful! Result:\n{json.dumps(ledger_data, indent=2)}")
        return ledger_data

    except subprocess.CalledProcessError as e:
        print("❌ Failed to submit or query transaction:")
        print(f"Return code: {e.returncode}")
        print(f"Standard Output: {e.stdout}")
        print(f"Standard Error: {e.stderr}")
        return None

if __name__ == "__main__":
    key = load_or_create_key()

    print("--- Step 1: Preparing Security Event ---")
    raw_event_payload = {
        "event_id": f"evt_{int(time.time())}_{uuid.uuid4().hex[:8]}",
        "threat_class": "DDoS",
        "confidence_score": 0.98,
        "source_ip": "192.168.1.105",
        "destination_ip": "10.0.0.50",
        "timestamp": str(time.time())
    }

    agent_id = "Agent-001-Org1"

    print("--- Step 2: Encrypting and Storing Payload in IPFS ---")
    payload_hash = store_off_chain_ipfs_encrypted(raw_event_payload, key)

    if not payload_hash:
        print("❌ Aborting because encrypted IPFS storage failed.")
        raise SystemExit(1)

    print("--- Step 3: Submitting CID to Live Ledger ---")
    print(f"Event ID: {raw_event_payload['event_id']}")
    print(f"Payload Hash (CID): {payload_hash}")

    ledger_data = invoke_chaincode(
        event_id=raw_event_payload['event_id'],
        payload_hash=payload_hash,
        timestamp=raw_event_payload['timestamp'],
        severity=raw_event_payload['threat_class'],
        agent_id=agent_id
    )

    if not ledger_data:
        print("❌ Aborting because blockchain verification failed.")
        raise SystemExit(1)

    print("\n--- Step 5: Retrieving and Decrypting Payload from IPFS ---")
    ipfs_data = retrieve_and_decrypt_from_ipfs(payload_hash, key)

    if not ipfs_data:
        print("❌ Failed to retrieve/decrypt payload from IPFS.")
        raise SystemExit(1)

    print("\n--- Step 6: Cross-Validation ---")
    if ledger_data["event_id"] == ipfs_data["event_id"]:
        print("✅ Cross-validation successful: Fabric record matches decrypted IPFS payload.")
    else:
        print("❌ Cross-validation failed: Fabric record does not match decrypted IPFS payload.")
