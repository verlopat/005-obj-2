"""Configuration for the compliance-scheduler service."""
import os
from dataclasses import dataclass


@dataclass
class Config:
    audit_api_url: str = os.getenv("AUDIT_API_URL", "http://audit-api:8001")
    schedule_daily_hour: int = int(os.getenv("SCHEDULE_DAILY_HOUR", "2"))
    schedule_weekly_day: str = os.getenv("SCHEDULE_WEEKLY_DAY", "mon")
    schedule_monthly_day: int = int(os.getenv("SCHEDULE_MONTHLY_DAY", "1"))
    frameworks: str = os.getenv("COMPLIANCE_FRAMEWORKS", "ISO27001,SOC2,NIST800-92")
    report_retention_days: int = int(os.getenv("REPORT_RETENTION_DAYS", "90"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    metrics_port: int = int(os.getenv("METRICS_PORT", "9093"))
    request_timeout_seconds: int = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "120"))

    def get_frameworks(self):
        return [f.strip() for f in self.frameworks.split(",") if f.strip()]


config = Config()
