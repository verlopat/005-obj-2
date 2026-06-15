"""Schemas for the audit-api service."""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ComplianceFramework(str, Enum):
    ISO_27001 = "ISO27001"
    SOC2 = "SOC2"
    NIST_800_92 = "NIST800-92"
    PCI_DSS = "PCIDSS"


class AuditEventRecord(BaseModel):
    event_id: str
    asset_id: str
    cloud_provider: str
    region: str
    severity: str
    attack_category: str
    description: str
    ipfs_cid: str
    sha256: str
    tx_id: str
    model_version: str
    detection_confidence: float
    signature: Optional[str] = None
    timestamp: str
    logged_by: str


class AuditTrailRequest(BaseModel):
    asset_id: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(default=100, ge=1, le=1000)


class SeverityQueryRequest(BaseModel):
    severity: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(default=100, ge=1, le=1000)


class IntegrityCheckResult(BaseModel):
    event_id: str
    status: str  # "VALID" | "TAMPERED" | "MISSING_IPFS"
    on_chain_sha256: str
    computed_sha256: Optional[str] = None
    match: Optional[bool] = None
    checked_at: datetime


class ComplianceReport(BaseModel):
    framework: str
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    total_events: int
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    by_asset: Dict[str, int]
    integrity_pass_rate: float
    events: List[AuditEventRecord]
    report_path: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    fabric_connected: bool
    version: str = "1.0.0"
