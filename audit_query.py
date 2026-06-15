#!/usr/bin/env python3
"""
audit_query.py
--------------
Audit Trail Querying and Compliance Reporting Interface (Objective 2 sub-component).

Provides:
  - Chain-of-custody retrieval for a cloud asset over a time window
  - Severity-based event filtering for compliance officers
  - Exportable JSON / CSV compliance reports (ISO 27001, SOC 2, NIST SP 800-92)
  - IPFS payload verification for each on-chain record

Usage (CLI):
    python audit_query.py --asset vm-prod-01 --from 2025-01-01 --to 2025-12-31 --format csv
    python audit_query.py --severity CRITICAL --format json

Usage (library):
    from audit_query import AuditQueryClient
    client = AuditQueryClient()
    events = client.get_event_history("vm-prod-01", from_ts="2025-01-01")
    client.export_report(events, fmt="csv", output_path="report.csv")

Dependencies:
    pip install hfc requests  (Fabric Python SDK)
"""

import argparse
import csv
import json
import logging
import os
import sys
from datetime import datetime, timezone
from io import StringIO
from typing import Any

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [AUDIT] %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Fabric REST gateway (fabric-gateway REST shim) or direct gRPC
FABRIC_GATEWAY_URL = os.environ.get("FABRIC_GATEWAY_URL", "http://localhost:8080")
CHANNEL_NAME       = os.environ.get("CHANNEL_NAME",       "mychannel")
CHAINCODE_NAME     = os.environ.get("CHAINCODE_NAME",     "security-logger")
IPFS_API_URL       = os.environ.get("IPFS_GATEWAY_URL",   "http://127.0.0.1:8080/ipfs")


class AuditQueryClient:
    """Retrieves and exports audit trails from the Hyperledger Fabric ledger."""

    def __init__(
        self,
        gateway_url: str = FABRIC_GATEWAY_URL,
        channel: str = CHANNEL_NAME,
        chaincode: str = CHAINCODE_NAME,
    ) -> None:
        self.base = gateway_url.rstrip("/")
        self.channel   = channel
        self.chaincode = chaincode

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
        return self._query(
            "QueryEventHistory",
            [cloud_asset_id, from_ts, to_ts],
        )

    def get_events_by_severity(self, severity: str) -> list[dict[str, Any]]:
        """Return all events matching *severity* (LOW / MEDIUM / HIGH / CRITICAL)."""
        return self._query("QueryEventsBySeverity", [severity.upper()])

    def verify_event(self, event_id: str) -> dict[str, Any] | None:
        """Return the on-chain record for *event_id*, or None if not found."""
        results = self._query("VerifyEvent", [event_id])
        return results[0] if results else None

    # ------------------------------------------------------------------
    # IPFS verification
    # ------------------------------------------------------------------

    def verify_ipfs_integrity(self, event: dict[str, Any]) -> bool:
        """
        Download the IPFS payload for *event* and verify its SHA-256 matches
        the on-chain hash.  Returns True if the payload is unmodified.
        """
        cid          = event.get("ipfs_cid", "")
        expected_hash = event.get("payload_hash", "")

        if cid.startswith("sha256:"):
            return cid == f"sha256:{expected_hash}"

        if not cid:
            logger.warning("Event %s has no IPFS CID — skipping integrity check", event.get("event_id"))
            return False

        try:
            import hashlib
            resp = requests.get(f"{IPFS_API_URL}/{cid}", timeout=10)
            resp.raise_for_status()
            actual = hashlib.sha256(resp.content).hexdigest()
            ok = actual == expected_hash
            if ok:
                logger.info("IPFS integrity OK  cid=%s", cid)
            else:
                logger.error("IPFS integrity FAIL  cid=%s  expected=%s  got=%s", cid, expected_hash, actual)
            return ok
        except Exception as exc:  # noqa: BLE001
            logger.error("IPFS fetch error for cid=%s: %s", cid, exc)
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
        *fmt* is 'json' or 'csv'.  If *output_path* is given, the report is
        written to disk; otherwise it is returned as a string.

        The report header includes generation timestamp and regulatory framework
        tags (ISO 27001, SOC 2, NIST SP 800-92).
        """
        meta = {
            "report_generated": datetime.now(timezone.utc).isoformat(),
            "regulatory_frameworks": ["ISO 27001", "SOC 2", "NIST SP 800-92"],
            "total_events": len(events),
            "channel": self.channel,
            "chaincode": self.chaincode,
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
            raise ValueError(f"Unsupported format: {fmt}. Choose 'json' or 'csv'.")

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(output)
            logger.info("Compliance report written to %s (%d events)", output_path, len(events))
        return output

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _query(
        self,
        function: str,
        args: list[str],
    ) -> list[dict[str, Any]]:
        """Submit a chaincode query to the Fabric REST gateway."""
        url = f"{self.base}/channels/{self.channel}/chaincodes/{self.chaincode}"
        params = {"fcn": function, "args": json.dumps(args), "peer": "peer0.org1.example.com"}
        try:
            resp = requests.get(url, params=params, timeout=15)
            resp.raise_for_status()
            result = resp.json().get("result", [])
            if isinstance(result, list):
                return result
            if isinstance(result, dict):
                return [result]
            return json.loads(result) if isinstance(result, str) else []
        except requests.HTTPError as exc:
            logger.error("Fabric query %s failed HTTP %s: %s", function, exc.response.status_code, exc)
        except Exception as exc:  # noqa: BLE001
            logger.error("Fabric query %s error: %s", function, exc)
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
    group.add_argument("--severity", help="Severity level to filter: LOW|MEDIUM|HIGH|CRITICAL")
    group.add_argument("--event-id", dest="event_id", help="Single event ID to verify")

    p.add_argument("--from",    dest="from_ts",     default="", help="Start timestamp (ISO 8601)")
    p.add_argument("--to",      dest="to_ts",       default="", help="End   timestamp (ISO 8601)")
    p.add_argument("--format",  dest="fmt",          default="json", choices=["json", "csv"])
    p.add_argument("--output",  dest="output_path",  default=None, help="Output file path")
    p.add_argument("--verify-ipfs", action="store_true", help="Verify IPFS payload integrity for each event")
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
