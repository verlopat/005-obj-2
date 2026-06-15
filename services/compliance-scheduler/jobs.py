"""Scheduled compliance report generation jobs."""
import logging
from datetime import datetime, timedelta
from typing import List

import requests

from config import config

logger = logging.getLogger(__name__)


def generate_daily_reports():
    """Generate compliance reports for the past 24 hours for all configured standards."""
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=24)
    logger.info("Generating daily compliance reports: %s to %s", start_time, end_time)
    _generate_reports_for_period(start_time, end_time, tag="daily")


def generate_weekly_reports():
    """Generate compliance reports for the past 7 days."""
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)
    logger.info("Generating weekly compliance reports: %s to %s", start_time, end_time)
    _generate_reports_for_period(start_time, end_time, tag="weekly")


def _generate_reports_for_period(start_time: datetime, end_time: datetime, tag: str):
    for standard in config.standards_list:
        try:
            response = requests.post(
                f"{config.audit_api_url}/api/v1/compliance/report",
                json={
                    "standard": standard,
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                    "output_format": "json",
                },
                timeout=config.request_timeout_seconds,
            )
            response.raise_for_status()
            report = response.json()
            logger.info(
                "[%s] %s report generated: %d events, sha256=%s",
                tag, standard, report.get("total_events", 0), report.get("report_sha256", "N/A"),
            )
        except Exception as exc:
            logger.error("[%s] Failed to generate %s report: %s", tag, standard, exc)


def run_integrity_spot_check():
    """Trigger integrity verification for recently logged events."""
    logger.info("Running integrity spot check")
    # Query recent events then verify each via /api/v1/audit/event/{id}
    # Implementation requires live Fabric + IPFS; logs warning in stub mode
    logger.info("Integrity spot check complete (stub mode)")
