#!/usr/bin/env python3
"""
pki_signer.py
-------------
Cryptographic event signing and non-repudiation layer (Objective 2 – PKI sub-component).

Each security event is ECDSA-signed with the detection agent's private key before
blockchain submission.  The corresponding X.509 certificate is issued by Hyperledger
Fabric CA (Fabric CA server) and stored in crypto-config/.

Usage:
    signer = EventSigner(key_path, cert_path)
    signature_hex = signer.sign_event(payload_dict)
    is_valid = signer.verify_signature(payload_dict, signature_hex, cert_path)

Dependencies:
    pip install cryptography
"""

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.x509 import load_pem_x509_certificate

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PKI] %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Paths can be overridden via environment variables
DEFAULT_KEY_PATH  = os.environ.get("AGENT_KEY_PATH",  "crypto-config/agent/keystore/agent_sk")
DEFAULT_CERT_PATH = os.environ.get("AGENT_CERT_PATH", "crypto-config/agent/signcerts/agent.pem")


class EventSigner:
    """Signs and verifies security event payloads using ECDSA P-256."""

    def __init__(self, key_path: str = DEFAULT_KEY_PATH, cert_path: str = DEFAULT_CERT_PATH):
        self.key_path  = Path(key_path)
        self.cert_path = Path(cert_path)
        self._private_key = self._load_private_key()
        logger.info("EventSigner initialised with key=%s cert=%s", self.key_path, self.cert_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sign_event(self, payload: dict[str, Any]) -> str:
        """
        Compute a canonical JSON representation of *payload*, sign it with the
        agent's ECDSA private key, and return the DER-encoded signature as a
        lowercase hex string.
        """
        canonical = self._canonicalise(payload)
        signature = self._private_key.sign(canonical, ec.ECDSA(hashes.SHA256()))
        hex_sig = signature.hex()
        logger.debug("Signed event  hash=%s  sig=%s…", self._sha256_hex(canonical), hex_sig[:16])
        return hex_sig

    @staticmethod
    def verify_signature(
        payload: dict[str, Any],
        signature_hex: str,
        cert_path: str = DEFAULT_CERT_PATH,
    ) -> bool:
        """
        Verify *signature_hex* against *payload* using the public key in *cert_path*.
        Returns True if the signature is valid.
        """
        try:
            cert_bytes = Path(cert_path).read_bytes()
            cert = load_pem_x509_certificate(cert_bytes)
            public_key: ec.EllipticCurvePublicKey = cert.public_key()  # type: ignore[assignment]

            canonical = EventSigner._canonicalise(payload)
            signature  = bytes.fromhex(signature_hex)
            public_key.verify(signature, canonical, ec.ECDSA(hashes.SHA256()))
            logger.info("Signature verification PASSED")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Signature verification FAILED: %s", exc)
            return False

    def get_agent_identity(self) -> str:
        """
        Return the Common Name (CN) from the agent's X.509 certificate.
        This value is stored as *agent_identity* on-chain.
        """
        try:
            cert_bytes = self.cert_path.read_bytes()
            cert = load_pem_x509_certificate(cert_bytes)
            cn = cert.subject.get_attributes_for_oid(
                __import__("cryptography.x509.oid", fromlist=["NameOID"]).NameOID.COMMON_NAME
            )[0].value
            return cn
        except Exception:  # noqa: BLE001
            return "unknown-agent"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_private_key(self) -> ec.EllipticCurvePrivateKey:
        if not self.key_path.exists():
            raise FileNotFoundError(
                f"Agent private key not found at {self.key_path}.\n"
                "Enrol the agent with Fabric CA first:\n"
                "  fabric-ca-client enroll -u http://admin:adminpw@localhost:7054"
            )
        key_bytes = self.key_path.read_bytes()
        key = serialization.load_pem_private_key(key_bytes, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("Only ECDSA private keys are supported")
        return key

    @staticmethod
    def _canonicalise(payload: dict[str, Any]) -> bytes:
        """Deterministic JSON serialisation (sorted keys, no spaces)."""
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _sha256_hex(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


if __name__ == "__main__":
    # Dev smoke test using a freshly generated ephemeral key (no Fabric CA needed)
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.backends import default_backend
    import tempfile, datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    # Generate ephemeral key + self-signed cert for testing
    priv = _ec.generate_private_key(_ec.SECP256R1(), default_backend())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-agent")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .sign(priv, hashes.SHA256(), default_backend())
    )

    with tempfile.TemporaryDirectory() as d:
        key_path  = os.path.join(d, "key.pem")
        cert_path = os.path.join(d, "cert.pem")
        Path(key_path).write_bytes(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        Path(cert_path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        signer = EventSigner(key_path=key_path, cert_path=cert_path)
        payload = {"event_id": "evt_001", "severity": "HIGH", "attack_category": "DDoS"}
        sig = signer.sign_event(payload)
        print(f"Signature  : {sig[:32]}…")
        print(f"Verified   : {EventSigner.verify_signature(payload, sig, cert_path)}")
        print(f"Agent CN   : {signer.get_agent_identity()}")
