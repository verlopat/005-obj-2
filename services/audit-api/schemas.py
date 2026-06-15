"""Pydantic schemas for the Audit API."""
from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field
import uuid


class ComplianceStandard(str, Enum):
    ISO27001 = "ISO-27001"
    SOC2     = "SOC2"
    NIST     = "NIST-SP-800-92"


class AuditTrailRequest(BaseModel):
    asset_id:   Optional[str] = None
    start_time: Optional[str] = None
    end_time:   Optional[str] = None
    page_size:  int = Field(default=20, ge=1, le=1000)


class SeverityQueryRequest(BaseModel):
    severity:   str
    start_time: Optional[str] = None
    end_time:   Optional[str] = None
    page_size:  int = Field(default=20, ge=1, le=1000)


class ComplianceReportRequest(BaseModel):
    standard:      ComplianceStandard = ComplianceStandard.ISO27001
    start_time:    Optional[str] = None
    end_time:      Optional[str] = None
    asset_ids:     Optional[List[str]] = None
    output_format: str = "json"


class IntegrityCheckRequest(BaseModel):
    event_ids: List[str]


class IntegrityCheckResult(BaseModel):
    event_id: str
    passed:   bool
    detail:   Optional[str] = None


class EventRecord(BaseModel):
    event_id:             str
    asset_id:             str
    cloud_provider:       str
    region:               str = ""
    severity:             str
    attack_category:      str = ""
    description:          str = ""
    detection_confidence: float = 0.0
    model_version:        str = ""
    tx_id:                str = ""
    block_number:         int = 0
    ipfs_cid:             str = ""
    timestamp:            str = ""
    org_msp:              str = ""


class ComplianceReport(BaseModel):
    standard:           str
    generated_at:       str
    period_start:       str
    period_end:         str
    total_events:       int
    critical_events:    int
    high_events:        int
    integrity_verified: bool
    non_repudiation:    str
    storage_backend:    str
    controls_satisfied: List[str]
    status:             str
    events:             List[EventRecord] = []
