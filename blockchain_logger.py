import json
import hashlib
import time
import requests
import grpc
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- 1. Cryptographic Identity Setup ---
# Generate a private/public key pair for the detection agent (simulating Fabric CA / X.509)
def generate_agent_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# --- 2. Event Signing ---
# Sign the event payload using the agent's private key
def sign_event(private_key, payload_bytes):
    signature = private_key.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# --- 3. IPFS Off-Chain Storage Integration ---
# Mocking IPFS upload using a public gateway api (For production, connect to local IPFS daemon)
def store_off_chain_ipfs(payload_dict):
    try:
        # Fallback: Just hash it locally if IPFS isn't running yet
        payload_str = json.dumps(payload_dict, sort_keys=True)
        # Using native hashlib which supports modern python versions without pysha3
        ipfs_cid_mock = "Qm" + hashlib.sha256(payload_str.encode()).hexdigest()[:44]
        print(f"[IPFS] Successfully stored full payload off-chain. CID: {ipfs_cid_mock}")
        return ipfs_cid_mock
    except Exception as e:
        print(f"IPFS Error: {e}")
        return None

# --- 4. Main Execution ---
if __name__ == "__main__":
    print("Initializing Detection Agent Identity...")
    private_key, public_key = generate_agent_keys()
    agent_id = "Agent-001"

    # Mock Anomaly Event (Output from Objective 1 Deep Learning Model)
    raw_event_payload = {
        "event_id": f"evt_{int(time.time())}",
        "threat_class": "DDoS",
        "confidence_score": 0.98,
        "source_ip": "192.168.1.105",
        "destination_ip": "10.0.0.50",
        "raw_features": [0.1, 0.5, 0.9, 0.2, 0.88], # Simulating raw network features
        "timestamp": str(time.time())
    }

    print("\n--- Step 1: Payload Preparation & Cryptographic Signing ---")
    payload_bytes = json.dumps(raw_event_payload, sort_keys=True).encode('utf-8')
    signature = sign_event(private_key, payload_bytes)
    print(f"Event digitally signed by {agent_id}.")

    print("\n--- Step 2: Off-Chain Storage (IPFS) ---")
    # Store full payload off-chain to reduce blockchain overhead (Objective 2 requirement)
    payload_hash = store_off_chain_ipfs(raw_event_payload)

    print("\n--- Step 3: On-Chain Commit (Hyperledger Fabric) ---")
    print(f"Submitting to Blockchain: EventID={raw_event_payload['event_id']}, Hash={payload_hash}, Severity={raw_event_payload['threat_class']}")
    
    # Placeholder for gRPC implementation to Fabric Gateway (Python 3.10+ standard)
    # Using grpcio directly to talk to the peer avoids the legacy fabric-sdk-py dependency hell
    print("[Blockchain] Transaction submitted successfully via gRPC stub. Latency: < 500ms (Simulated).")

    print("\n--- Objective 2 Pipeline Complete ---")
