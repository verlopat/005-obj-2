"""Configuration for the compliance-scheduler service."""
import os
from dataclasses import dataclass

@dataclass
class Config:
    audit_api_url: str = os.getenv("AUDIT_API_URL", "http://audit-api:8001")
    schedule_daily_hour: int = int(os.getenv("SCHEDULE_DAILY_HOUR", "2"))
    schedule_weekly_day: str = os.getenv("SCHEDULE_WEEKLY_DAY", "monday")
    standards: str = os.getenv("COMPLIANCE_STANDARDS", "ISO-27001,SOC-2,NIST-SP-800-92")
    reports_output_dir: str = os.getenv("REPORTS_OUTPUT_DIR", "/app/reports")
    request_timeout_seconds: int = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "300"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    @property
    def standards_list(self):
        return [s.strip() for s in self.standards.split(",") if s.strip()]

config = Config()
