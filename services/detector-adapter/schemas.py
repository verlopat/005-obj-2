"""Pydantic v2 schemas for the Detector Adapter."""
import uuid
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class SecurityEventRequest(BaseModel):
    event_id:             Optional[uuid.UUID] = Field(default_factory=uuid.uuid4)
    asset_id:             str
    cloud_provider:       str = ""
    region:               str = ""
    severity:             SeverityLevel
    attack_category:      str = ""
    description:          str = ""
    detection_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    model_version:        str = ""


class BatchEventRequest(BaseModel):
    events: List[SecurityEventRequest]


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
