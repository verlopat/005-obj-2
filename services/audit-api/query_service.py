"""Fabric query service — wraps chaincode query calls."""
import json
import logging
from datetime import datetime
from typing import List, Optional

from config import config
from schemas import AuditTrailRequest, EventRecord, SeverityQueryRequest

logger = logging.getLogger(__name__)

try:
    from hfc.fabric import Client as HFCClient
except ImportError:
    HFCClient = None
    logger.warning("hfc not installed — QueryService in stub mode")


class QueryService:
    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            if HFCClient is None:
                raise RuntimeError("fabric-sdk-py not installed")
            self._client = HFCClient(net_profile=None)
        return self._client

    def _parse_records(self, raw_results: list) -> List[EventRecord]:
        records = []
        for item in raw_results:
            try:
                if isinstance(item, str):
                    item = json.loads(item)
                records.append(EventRecord(**item))
            except Exception as exc:
                logger.warning("Failed to parse record: %s", exc)
        return records

    def query_audit_trail(
        self,
        asset_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        page_size: int = 50,
    ) -> List[EventRecord]:
        """Query event history for a cloud asset using CouchDB rich query."""
        start_str = start_time.isoformat() if start_time else ""
        end_str = end_time.isoformat() if end_time else ""
        logger.info("Querying audit trail for asset=%s from=%s to=%s",
                    asset_id, start_str, end_str)
        # Production: invoke chaincode QueryEventHistory
        # Stub: return empty list
        return []

    def query_by_severity(
        self,
        severity: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        page_size: int = 50,
    ) -> List[EventRecord]:
        """Query events by severity level."""
        start_str = start_time.isoformat() if start_time else ""
        end_str = end_time.isoformat() if end_time else ""
        logger.info("Querying events severity=%s from=%s to=%s", severity, start_str, end_str)
        return []

    def get_event(self, event_id: str) -> Optional[EventRecord]:
        """Fetch a single event record from the ledger."""
        logger.info("Fetching event %s", event_id)
        return None


query_service = QueryService()
