"""Internal schemas for the blockchain-logger service."""
from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel

class SecurityEventMessage(BaseModel):
    event_id: str
    asset_id: str
    cloud_provider: str
    region: str
    severity: str
    attack_category: str = "UNKNOWN"
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    detection_confidence: float = 1.0
    model_version: str = "v1.0"
    raw_payload: Optional[Dict[str, Any]] = None
    timestamp: str

    class Config:
        extra = "allow"

class LogResult(BaseModel):
    event_id: str
    ipfs_cid: str
    sha256: str
    tx_id: str
    block_number: Optional[int] = None
    logged_at: datetime
    duration_ms: float
