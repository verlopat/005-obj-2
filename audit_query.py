#!/usr/bin/env python3
"""
audit_query.py
--------------
Audit Trail Querying and Compliance Reporting Interface (Objective 2).

Provides:
  - Chain-of-custody retrieval for a cloud asset over a time window
  - Severity-based event filtering for compliance officers
  - Exportable JSON / CSV compliance reports (ISO 27001, SOC 2, NIST SP 800-92)
  - IPFS payload integrity verification (rehash downloaded bytes vs on-chain hash)
  - Schema validation — logs loudly when ledger records are malformed

Usage (CLI):
    python audit_query.py --asset vm-prod-01 --from 2025-01-01 --to 2025-12-31 --format csv
    python audit_query.py --severity CRITICAL --format json
    python audit_query.py --event-id evt_abc123 --verify-ipfs

Usage (library):
    from audit_query import AuditQueryClient
    client = AuditQueryClient()
    events = client.get_event_history("vm-prod-01", from_ts="2025-01-01")
    client.export_report(events, fmt="csv", output_path="report.csv")

Dependencies:
    pip install requests
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from io import StringIO
from typing import Any

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AUDIT] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration  —  chaincode name MUST match the deployed chaincode
# ---------------------------------------------------------------------------
FABRIC_GATEWAY_URL = os.environ.get("FABRIC_GATEWAY_URL", "http://localhost:8080")
CHANNEL_NAME       = os.environ.get("CHANNEL_NAME",       "mychannel")
CHAINCODE_NAME     = os.environ.get("CHAINCODE_NAME",     "security_logger")  # fixed from security-logger
IPFS_GATEWAY_URL   = os.environ.get("IPFS_GATEWAY_URL",   "http://127.0.0.1:8080/ipfs")
IPFS_API_URL       = os.environ.get("IPFS_API_URL",       "http://127.0.0.1:5001")

# Required fields for a valid on-chain event record (schema validation)
_REQUIRED_FIELDS = {
    "event_id", "payload_hash", "ipfs_cid",
    "timestamp", "severity", "attack_category",
    "detection_confidence", "cloud_asset_id",
    "agent_identity", "model_version",
}


def _validate_event_schema(event: dict[str, Any]) -> bool:
    """Return True if event has all required fields; log loudly if not."""
    missing = _REQUIRED_FIELDS - set(event.keys())
    if missing:
        log.error(
            "Malformed ledger event (event_id=%s), missing keys: %s",
            event.get("event_id", "<unknown>"),
            sorted(missing),
        )
        return False
    return True


class AuditQueryClient:
    """Retrieves and exports audit trails from the Hyperledger Fabric ledger."""

    def __init__(
        self,
        gateway_url: str = FABRIC_GATEWAY_URL,
        channel: str = CHANNEL_NAME,
        chaincode: str = CHAINCODE_NAME,
    ) -> None:
        self.base      = gateway_url.rstrip("/")
        self.channel   = channel
        self.chaincode = chaincode
        log.info(
            "AuditQueryClient ready  chaincode=%s  channel=%s  gateway=%s",
            self.chaincode, self.channel, self.base,
        )

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def get_event_history(
        self,
        cloud_asset_id: str,
        from_ts: str = "",
        to_ts: str = "",
    ) -> list[dict[str, Any]]:
        """
        Return the ordered audit trail for *cloud_asset_id*.
        ISO 8601 timestamps (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ) for filtering.
        """
        events = self._query("QueryEventHistory", [cloud_asset_id, from_ts, to_ts])
        return [e for e in events if _validate_event_schema(e)]

    def get_events_by_severity(self, severity: str) -> list[dict[str, Any]]:
        """Return all events matching *severity* (LOW / MEDIUM / HIGH / CRITICAL)."""
        events = self._query("QueryEventsBySeverity", [severity.upper()])
        return [e for e in events if _validate_event_schema(e)]

    def verify_event(self, event_id: str) -> dict[str, Any] | None:
        """Return the on-chain record for *event_id*, or None if not found."""
        results = self._query("VerifyEvent", [event_id])
        if not results:
            return None
        ev = results[0]
        _validate_event_schema(ev)
        return ev

    # ------------------------------------------------------------------
    # IPFS integrity verification
    # ------------------------------------------------------------------

    def verify_ipfs_integrity(self, event: dict[str, Any]) -> bool:
        """
        Download the IPFS payload for *event* and verify that its SHA-256
        matches *event[payload_hash]*.  This confirms off-chain content
        has not been tampered with since it was committed to the ledger.

        payload_hash is the SHA-256 of the raw bytes stored in IPFS,
        NOT the IPFS CID.  They are stored in separate on-chain fields.
        """
        cid           = event.get("ipfs_cid", "")
        expected_hash = event.get("payload_hash", "")

        if cid.startswith("sha256:"):
            # Hash-only fallback mode — compare directly
            result = cid == f"sha256:{expected_hash}"
            log.info("[IPFS] Hash-only fallback verify for event_id=%s: %s",
                     event.get("event_id"), "PASS" if result else "FAIL")
            return result

        if not cid or not expected_hash:
            log.warning("[IPFS] Cannot verify: missing cid or payload_hash in event %s",
                        event.get("event_id"))
            return False

        try:
            resp = requests.post(
                f"{IPFS_API_URL}/api/v0/cat",
                params={"arg": cid},
                timeout=15,
            )
            resp.raise_for_status()
            actual_hash = hashlib.sha256(resp.content).hexdigest()
            ok = actual_hash == expected_hash
            if ok:
                log.info("[IPFS] Integrity PASS  cid=%s  event_id=%s", cid, event.get("event_id"))
            else:
                log.error(
                    "[IPFS] Integrity FAIL  cid=%s  expected=%s  got=%s",
                    cid, expected_hash, actual_hash,
                )
            return ok
        except Exception as exc:  # noqa: BLE001
            log.error("[IPFS] Fetch error for cid=%s: %s", cid, exc)
            return False

    # ------------------------------------------------------------------
    # Compliance export
    # ------------------------------------------------------------------

    def export_report(
        self,
        events: list[dict[str, Any]],
        fmt: str = "json",
        output_path: str | None = None,
    ) -> str:
        """
        Export *events* as a compliance report.
        *fmt* is 'json' or 'csv'.  Writes to *output_path* if given.

        Report header tags: ISO 27001, SOC 2, NIST SP 800-92.
        """
        meta = {
            "report_generated":     datetime.now(timezone.utc).isoformat(),
            "regulatory_frameworks": ["ISO 27001", "SOC 2", "NIST SP 800-92"],
            "total_events":          len(events),
            "channel":               self.channel,
            "chaincode":             self.chaincode,
        }

        if fmt.lower() == "json":
            output = json.dumps({"meta": meta, "events": events}, indent=2)

        elif fmt.lower() == "csv":
            fields = [
                "event_id", "timestamp", "severity", "attack_category",
                "detection_confidence", "cloud_asset_id", "agent_identity",
                "payload_hash", "ipfs_cid", "model_version",
            ]
            buf = StringIO()
            writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(events)
            output = buf.getvalue()

        else:
            raise ValueError(f"Unsupported format: {fmt!r}. Choose 'json' or 'csv'.")

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(output)
            log.info("Compliance report written to %s (%d events)", output_path, len(events))
        return output

    # ------------------------------------------------------------------
    # Internal  —  Fabric REST gateway query
    # ------------------------------------------------------------------

    def _query(self, function: str, args: list[str]) -> list[dict[str, Any]]:
        """Submit a chaincode query to the Fabric REST gateway."""
        url = f"{self.base}/channels/{self.channel}/chaincodes/{self.chaincode}"
        params = {
            "fcn":  function,
            "args": json.dumps(args),
            "peer": "peer0.org1.example.com",
        }
        try:
            resp = requests.get(url, params=params, timeout=15)
            resp.raise_for_status()
            result = resp.json().get("result", [])
            if isinstance(result, list):  return result
            if isinstance(result, dict):  return [result]
            if isinstance(result, str):   return json.loads(result)
            return []
        except requests.HTTPError as exc:
            log.error("Fabric query %s HTTP %s: %s", function, exc.response.status_code, exc)
        except Exception as exc:  # noqa: BLE001
            log.error("Fabric query %s error: %s", function, exc)
        return []


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Audit trail query and compliance reporting for the blockchain security logger"
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--asset",    help="Cloud asset ID to query history for")
    group.add_argument("--severity", help="Severity level: LOW|MEDIUM|HIGH|CRITICAL")
    group.add_argument("--event-id", dest="event_id", help="Single event ID to verify")

    p.add_argument("--from",        dest="from_ts",    default="", help="Start timestamp (ISO 8601)")
    p.add_argument("--to",          dest="to_ts",       default="", help="End   timestamp (ISO 8601)")
    p.add_argument("--format",      dest="fmt",          default="json", choices=["json", "csv"])
    p.add_argument("--output",      dest="output_path",  default=None,  help="Output file path")
    p.add_argument("--verify-ipfs", action="store_true", help="Verify IPFS payload integrity per event")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    client = AuditQueryClient()

    if args.asset:
        events = client.get_event_history(args.asset, args.from_ts, args.to_ts)
    elif args.severity:
        events = client.get_events_by_severity(args.severity)
    else:
        ev = client.verify_event(args.event_id)
        events = [ev] if ev else []

    if args.verify_ipfs:
        for ev in events:
            ev["_ipfs_integrity"] = client.verify_ipfs_integrity(ev)

    report = client.export_report(events, fmt=args.fmt, output_path=args.output_path)
    if not args.output_path:
        print(report)

    sys.exit(0 if events else 1)
