"""Schemas for the audit-api service."""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class ComplianceStandard(str, Enum):
    ISO_27001 = "ISO-27001"
    SOC2 = "SOC-2"
    NIST_800_92 = "NIST-SP-800-92"
    PCI_DSS = "PCI-DSS"
    GDPR = "GDPR"

class EventRecord(BaseModel):
    event_id: str
    asset_id: str
    severity: str
    attack_category: str
    description: str
    ipfs_cid: str
    sha256: str
    tx_id: str
    timestamp: str
    detection_confidence: float
    model_version: str
    logged_by_msp: str
    block_number: Optional[int] = None
    signature: Optional[str] = None

class AuditTrailRequest(BaseModel):
    asset_id: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    page_size: int = Field(default=50, ge=1, le=500)

class SeverityQueryRequest(BaseModel):
    severity: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    page_size: int = Field(default=50, ge=1, le=500)

class ComplianceReportRequest(BaseModel):
    standard: ComplianceStandard
    start_time: datetime
    end_time: datetime
    asset_ids: Optional[List[str]] = None
    output_format: str = Field(default="json", regex="^(json|csv|pdf)$")

class IntegrityCheckRequest(BaseModel):
    event_id: str

class IntegrityCheckResult(BaseModel):
    event_id: str
    chain_sha256: str
    ipfs_sha256: str
    match: bool
    ipfs_cid: str
    verified_at: datetime

class ComplianceReport(BaseModel):
    standard: str
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    total_events: int
    events_by_severity: Dict[str, int]
    events_by_category: Dict[str, int]
    high_confidence_events: int
    integrity_violations: int
    events: List[EventRecord]
    report_sha256: str
