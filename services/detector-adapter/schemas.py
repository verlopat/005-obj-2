"""Pydantic v2 schemas for the Detector Adapter."""
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class CloudProvider(str, Enum):
    AWS   = "AWS"
    GCP   = "GCP"
    AZURE = "Azure"
    OTHER = "OTHER"


class SecurityEventRequest(BaseModel):
    event_id:             uuid.UUID        = Field(default_factory=uuid.uuid4)
    asset_id:             str              = Field(..., min_length=1)
    cloud_provider:       CloudProvider    = CloudProvider.AWS
    region:               str              = ""
    severity:             SeverityLevel    = SeverityLevel.LOW
    attack_category:      str              = ""
    description:          str              = ""
    detection_confidence: float            = Field(default=0.0, ge=0.0, le=1.0)
    model_version:        str              = "v1.0"
    raw_payload:          Optional[Dict]   = None


class BatchEventRequest(BaseModel):
    events: List[SecurityEventRequest] = Field(..., min_length=1)


class EventResponse(BaseModel):
    event_id: str
    status:   str
    message:  Optional[str] = None


class BatchEventResponse(BaseModel):
    accepted: int
    rejected: int
    results:  List[EventResponse]


class HealthResponse(BaseModel):
    status:          str
    kafka_connected: bool
