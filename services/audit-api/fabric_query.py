"""Read-only Fabric query helpers for the audit API."""
import json
import logging
from typing import Any, Dict, List, Optional

from config import config

logger = logging.getLogger(__name__)

try:
    from hfc.fabric import Client as HFClient
    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False
    logger.warning("hfc not installed — Fabric query in stub mode")


class FabricQueryClient:
    """Issues chaincode queries (read-only) against the security_logger chaincode."""

    def _query(self, fcn: str, args: List[str]) -> Any:
        if not _SDK_AVAILABLE:
            logger.debug("STUB query %s %s", fcn, args)
            return []
        # In live deployment: use hfc channel.chaincode_query()
        raise NotImplementedError("Live Fabric SDK query not wired in this stub")

    def get_event(self, event_id: str) -> Optional[Dict]:
        result = self._query("GetSecurityEvent", [event_id])
        return result if result else None

    def query_history(self, asset_id: str, start_time: str, end_time: str) -> List[Dict]:
        return self._query("QueryEventHistory", [asset_id, start_time, end_time])

    def query_by_severity(self, severity: str, start_time: str, end_time: str) -> List[Dict]:
        return self._query("QueryEventsBySeverity", [severity, start_time, end_time])

    def get_all_events(self, page_size: int = 100, bookmark: str = "") -> Dict:
        return self._query("GetAllEvents", [str(page_size), bookmark]) or {"records": [], "bookmark": ""}


fabric_query = FabricQueryClient()
