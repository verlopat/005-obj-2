"""Configuration for the compliance-scheduler service."""
import os
from dataclasses import dataclass


@dataclass
class Config:
    audit_api_url: str      = os.getenv("AUDIT_API_URL",      "http://audit-api:8001")
    report_output_dir: str  = os.getenv("REPORT_OUTPUT_DIR",  "/reports")
    schedule_daily: str     = os.getenv("SCHEDULE_DAILY",     "02:00")
    schedule_weekly: str    = os.getenv("SCHEDULE_WEEKLY",    "sunday 03:00")
    frameworks: str         = os.getenv("FRAMEWORKS",         "ISO27001,SOC2,NIST_SP_800_92")
    log_level: str          = os.getenv("LOG_LEVEL",          "INFO")
    metrics_port: int       = int(os.getenv("METRICS_PORT",   "9093"))
    report_retention_days: int = int(os.getenv("REPORT_RETENTION_DAYS", "90"))

    @property
    def framework_list(self):
        return [f.strip() for f in self.frameworks.split(",") if f.strip()]


config = Config()
