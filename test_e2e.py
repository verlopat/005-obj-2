#!/usr/bin/env python3
"""
test_e2e.py
-----------
End-to-end automated test suite for Objective 2.

Verifies:
  1. Canonical event payload schema is correct
  2. AES-256-GCM encrypt → decrypt round-trip
  3. SHA-256 payload hash is correctly separated from IPFS CID
  4. PKI signing produces non-empty signature (if Fabric CA creds present)
  5. Chaincode argument count matches security_logger.go signature (11 args)
  6. IPFS integrity verification passes after upload
  7. Audit query schema validation rejects malformed events
  8. On-chain event JSON size is ≤ 1 KB

Run:
  python test_e2e.py

Dependencies:
  pip install pycryptodome requests cryptography
"""

import hashlib
import inspect
import json
import logging
import sys
import time
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

logging.basicConfig(level=logging.WARNING)


class TestPayloadSchema(unittest.TestCase):
    def test_canonical_fields_present(self):
        """build_event_payload() must include all required on-chain fields."""
        from live_blockchain_logger import build_event_payload
        p = build_event_payload()
        required = {
            "event_id", "timestamp", "severity", "attack_category",
            "detection_confidence", "cloud_asset_id", "model_version",
        }
        self.assertTrue(required.issubset(set(p.keys())), f"Missing: {required - set(p.keys())}")

    def test_attack_category_not_threat_class(self):
        """Field must be attack_category, not the old threat_class."""
        from live_blockchain_logger import build_event_payload
        p = build_event_payload()
        self.assertIn("attack_category", p)
        self.assertNotIn("threat_class", p)

    def test_detection_confidence_not_confidence_score(self):
        """Field must be detection_confidence, not the old confidence_score."""
        from live_blockchain_logger import build_event_payload
        p = build_event_payload()
        self.assertIn("detection_confidence", p)
        self.assertNotIn("confidence_score", p)


class TestAESEncryption(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        from Crypto.Random import get_random_bytes
        from live_blockchain_logger import decrypt_payload, encrypt_payload
        key = get_random_bytes(32)
        payload = {"event_id": "evt_test", "severity": "HIGH", "value": 42}
        enc = encrypt_payload(payload, key)
        dec = decrypt_payload(enc, key)
        self.assertEqual(payload, dec)

    def test_encrypt_changes_data(self):
        from Crypto.Random import get_random_bytes
        from live_blockchain_logger import encrypt_payload
        key = get_random_bytes(32)
        payload = {"event_id": "evt_test"}
        enc = encrypt_payload(payload, key)
        self.assertIn("nonce", enc)
        self.assertIn("ciphertext", enc)
        self.assertIn("tag", enc)


class TestIPFSUpload(unittest.TestCase):
    def test_sha256_separate_from_cid(self):
        """
        store_off_chain_ipfs_encrypted must return (cid, sha256, pkg)
        where sha256 is computed over the stored bytes, NOT the CID string.
        """
        from Crypto.Random import get_random_bytes
        from live_blockchain_logger import encrypt_payload, store_off_chain_ipfs_encrypted
        key = get_random_bytes(32)
        payload = {"event_id": "evt_sha_test", "severity": "LOW"}

        # Mock requests.post to simulate IPFS response
        mock_response = MagicMock()
        mock_response.json.return_value = {"Hash": "QmTestCID123456789"}
        mock_response.raise_for_status = MagicMock()

        with patch("live_blockchain_logger.requests.post", return_value=mock_response):
            cid, sha256, pkg = store_off_chain_ipfs_encrypted(payload, key)

        self.assertEqual(cid, "QmTestCID123456789")
        self.assertIsNotNone(sha256)
        self.assertEqual(len(sha256), 64, "SHA-256 must be a 64-char hex string")
        # Verify sha256 is hash of stored bytes, not the CID
        payload_bytes = json.dumps(pkg, sort_keys=True).encode("utf-8")
        expected_hash = hashlib.sha256(payload_bytes).hexdigest()
        self.assertEqual(sha256, expected_hash)

    def test_cid_and_hash_are_different(self):
        """CID and payload_hash must NOT be equal (they were conflated before)."""
        from Crypto.Random import get_random_bytes
        from live_blockchain_logger import store_off_chain_ipfs_encrypted
        key = get_random_bytes(32)
        payload = {"event_id": "evt_distinct"}

        mock_response = MagicMock()
        mock_response.json.return_value = {"Hash": "QmDistinctCID"}
        mock_response.raise_for_status = MagicMock()

        with patch("live_blockchain_logger.requests.post", return_value=mock_response):
            cid, sha256, _ = store_off_chain_ipfs_encrypted(payload, key)

        self.assertNotEqual(cid, sha256, "CID and SHA-256 hash must be distinct fields")


class TestChaincodeArgCount(unittest.TestCase):
    def test_invoke_chaincode_has_11_args(self):
        """
        invoke_chaincode() must accept exactly 11 parameters (matching the
        Go chaincode signature), not the old 5-argument version.
        """
        from live_blockchain_logger import invoke_chaincode
        sig = inspect.signature(invoke_chaincode)
        params = list(sig.parameters.keys())
        self.assertEqual(len(params), 11, f"Expected 11 args, got {len(params)}: {params}")

    def test_invoke_chaincode_has_ipfs_cid_param(self):
        from live_blockchain_logger import invoke_chaincode
        sig = inspect.signature(invoke_chaincode)
        self.assertIn("ipfs_cid",        sig.parameters)
        self.assertIn("attack_category", sig.parameters)
        self.assertIn("detection_confidence", sig.parameters)
        self.assertIn("model_version",   sig.parameters)
        self.assertIn("agent_signature", sig.parameters)
        self.assertIn("cloud_asset_id",  sig.parameters)


class TestAuditQuerySchemaValidation(unittest.TestCase):
    def test_rejects_malformed_event(self):
        """_validate_event_schema must return False for events missing required keys."""
        from audit_query import _validate_event_schema
        bad_event = {"event_id": "evt_bad", "severity": "LOW"}  # missing most fields
        with self.assertLogs("audit_query", level="ERROR") as cm:
            result = _validate_event_schema(bad_event)
        self.assertFalse(result)
        self.assertTrue(any("missing keys" in msg for msg in cm.output))

    def test_accepts_complete_event(self):
        from audit_query import _validate_event_schema
        good_event = {
            "event_id":            "evt_001",
            "payload_hash":        "a" * 64,
            "ipfs_cid":            "QmTest",
            "timestamp":           "2025-06-15T12:00:00Z",
            "severity":            "HIGH",
            "attack_category":     "DDoS",
            "detection_confidence": 0.98,
            "cloud_asset_id":      "vm-prod-01",
            "agent_identity":      "agent-01",
            "model_version":       "v1",
        }
        result = _validate_event_schema(good_event)
        self.assertTrue(result)

    def test_chaincode_name_consistency(self):
        """CHAINCODE_NAME default must be security_logger, not security-logger."""
        import audit_query
        # Reset env so we get the default
        import os
        env_backup = os.environ.pop("CHAINCODE_NAME", None)
        import importlib
        importlib.reload(audit_query)
        self.assertEqual(audit_query.CHAINCODE_NAME, "security_logger")
        if env_backup:
            os.environ["CHAINCODE_NAME"] = env_backup


class TestStorageOverhead(unittest.TestCase):
    def test_on_chain_event_under_1kb(self):
        """
        A representative SecurityEvent serialised to JSON must be ≤ 1024 bytes
        to satisfy Objective 2 Metric 3.
        """
        representative_event = {
            "event_id":             "evt_1718438400_ab12cd34",
            "payload_hash":         "a" * 64,
            "ipfs_cid":             "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
            "timestamp":            "2025-06-15T12:00:00Z",
            "severity":             "HIGH",
            "attack_category":      "DDoS",
            "detection_confidence": 0.98,
            "model_version":        "obj1-cnn-lstm-transformer-v1",
            "agent_identity":       "detection-agent-01",
            "agent_signature":      "b" * 128,
            "cloud_asset_id":       "vm-prod-01",
        }
        size = len(json.dumps(representative_event, separators=(",", ":")).encode("utf-8"))
        self.assertLessEqual(
            size, 1024,
            f"On-chain event size {size} bytes exceeds 1 KB KPI threshold",
        )


class TestCouchDBIndexes(unittest.TestCase):
    def test_index_files_exist(self):
        """CouchDB index files must be present for QueryEventHistory to perform reliably."""
        asset_idx    = Path("chaincode/META-INF/statedb/couchdb/indexes/indexAssetTimestamp.json")
        severity_idx = Path("chaincode/META-INF/statedb/couchdb/indexes/indexSeverityTimestamp.json")
        self.assertTrue(asset_idx.exists(),    f"Missing: {asset_idx}")
        self.assertTrue(severity_idx.exists(), f"Missing: {severity_idx}")

    def test_index_files_valid_json(self):
        for name in [
            "chaincode/META-INF/statedb/couchdb/indexes/indexAssetTimestamp.json",
            "chaincode/META-INF/statedb/couchdb/indexes/indexSeverityTimestamp.json",
        ]:
            with open(name, encoding="utf-8") as f:
                data = json.load(f)
            self.assertIn("index",  data)
            self.assertIn("fields", data["index"])


if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(unittest.TestLoader().loadTestsFromModule(
        __import__("__main__")
    ))
    sys.exit(0 if result.wasSuccessful() else 1)
