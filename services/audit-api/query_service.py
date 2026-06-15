"""Fabric query service for the audit-api."""
import json
import logging
from datetime import datetime
from typing import List, Optional

from config import config
from schemas import AuditEventRecord

logger = logging.getLogger(__name__)

try:
    from hfc.fabric import Client as HFCClient
    HFC_AVAILABLE = True
except ImportError:
    HFCClient = None
    HFC_AVAILABLE = False


class FabricQueryService:
    def __init__(self):
        self._client = None
        self._initialized = False

    def _ensure_init(self):
        if self._initialized:
            return
        if not HFC_AVAILABLE:
            raise RuntimeError("hfc SDK not installed")
        self._client = HFCClient(net_profile=None)
        self._initialized = True
        logger.info("Fabric query client initialized")

    def _invoke_query(self, function: str, args: list) -> list:
        self._ensure_init()
        logger.info("Query %s args=%s", function, args)
        # In production, use hfc channel.query_by_chaincode()
        # Returning empty list as safe stub for environments without live Fabric
        return []

    def get_event(self, event_id: str) -> Optional[AuditEventRecord]:
        results = self._invoke_query("GetSecurityEvent", [event_id])
        if not results:
            return None
        return AuditEventRecord(**results[0])

    def get_event_history(
        self,
        asset_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditEventRecord]:
        args = [
            asset_id,
            start_time.isoformat() if start_time else "",
            end_time.isoformat() if end_time else "",
            str(limit),
        ]
        results = self._invoke_query("QueryEventHistory", args)
        return [AuditEventRecord(**r) for r in results]

    def get_events_by_severity(
        self,
        severity: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditEventRecord]:
        args = [
            severity,
            start_time.isoformat() if start_time else "",
            end_time.isoformat() if end_time else "",
            str(limit),
        ]
        results = self._invoke_query("QueryEventsBySeverity", args)
        return [AuditEventRecord(**r) for r in results]

    def is_healthy(self) -> bool:
        try:
            self._ensure_init()
            return True
        except Exception:
            return False


query_service = FabricQueryService()
