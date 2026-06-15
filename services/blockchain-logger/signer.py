"""ECDSA P-256 event signing for non-repudiation."""
import base64
import logging
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_pem_x509_certificate

from config import config
from crypto_utils import canonical_json

logger = logging.getLogger(__name__)


class EventSigner:
    def __init__(self):
        self._private_key: Optional[ec.EllipticCurvePrivateKey] = None
        self._cert_fingerprint: Optional[str] = None
        self._load_keys()

    def _load_keys(self):
        key_path  = Path(config.signing_key_path)
        cert_path = Path(config.signing_cert_path)
        if not key_path.exists() or not cert_path.exists():
            logger.warning("Signing keys not found — signing disabled")
            return
        with key_path.open("rb") as f:
            self._private_key = serialization.load_pem_private_key(f.read(), password=None)
        with cert_path.open("rb") as f:
            cert = load_pem_x509_certificate(f.read())
            self._cert_fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        logger.info("Event signer ready. Cert fingerprint: %s", self._cert_fingerprint)

    def sign(self, payload: dict) -> Optional[str]:
        """Return base64-encoded DER ECDSA signature, or None if disabled."""
        if self._private_key is None:
            return None
        sig = self._private_key.sign(canonical_json(payload), ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(sig).decode("utf-8")

    @property
    def enabled(self) -> bool:
        return self._private_key is not None

    def cert_fingerprint(self) -> Optional[str]:
        return self._cert_fingerprint


signer = EventSigner()
