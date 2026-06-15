"""Pydantic schemas for the detector-adapter ingestion API."""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, validator

class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AttackCategory(str, Enum):
    DDOS = "DDOS"
    INTRUSION = "INTRUSION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    RANSOMWARE = "RANSOMWARE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    ANOMALY = "ANOMALY"
    UNKNOWN = "UNKNOWN"

class SecurityEventRequest(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    asset_id: str = Field(..., min_length=1, max_length=256)
    cloud_provider: str = Field(..., min_length=1, max_length=64)
    region: str = Field(..., min_length=1, max_length=64)
    severity: SeverityLevel
    attack_category: AttackCategory = AttackCategory.UNKNOWN
    description: str = Field(..., min_length=1, max_length=4096)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    detection_confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    model_version: str = Field(default="v1.0", max_length=32)
    raw_payload: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    @validator("timestamp", pre=True, always=True)
    def set_timestamp(cls, v):
        return v or datetime.utcnow()

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat() + "Z", UUID: str}

class BatchEventRequest(BaseModel):
    events: List[SecurityEventRequest] = Field(..., min_items=1, max_items=100)

class EventResponse(BaseModel):
    event_id: str
    status: str
    kafka_offset: Optional[int] = None
    message: str = "Event accepted"

class BatchEventResponse(BaseModel):
    accepted: int
    rejected: int
    results: List[EventResponse]

class HealthResponse(BaseModel):
    status: str
    kafka_connected: bool
    version: str = "1.0.0"
