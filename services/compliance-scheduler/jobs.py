"""Scheduled compliance report jobs."""
import logging
from datetime import datetime, timedelta
from typing import Optional

import requests
from prometheus_client import Counter

from config import config

logger = logging.getLogger(__name__)

REPORTS_GENERATED = Counter("scheduler_reports_generated_total", "Reports generated", ["framework"])
REPORTS_FAILED = Counter("scheduler_reports_failed_total", "Report generation failures", ["framework"])


class ComplianceJobRunner:
    def __init__(self):
        self._session = requests.Session()
        self._session.headers["Content-Type"] = "application/json"

    def run_daily_report(self):
        """Generate previous 24h compliance reports for all frameworks."""
        logger.info("Running daily compliance reports")
        end = datetime.utcnow()
        start = end - timedelta(days=1)
        self._run_reports(days=1)

    def run_weekly_report(self):
        """Generate previous 7-day compliance reports."""
        logger.info("Running weekly compliance reports")
        self._run_reports(days=7)

    def run_monthly_report(self):
        """Generate previous 30-day compliance reports."""
        logger.info("Running monthly compliance reports")
        self._run_reports(days=30)

    def _run_reports(self, days: int):
        for framework in config.get_frameworks():
            try:
                resp = self._session.post(
                    f"{config.audit_api_url}/api/v1/compliance/report",
                    params={"framework": framework, "days": days},
                    timeout=config.request_timeout_seconds,
                )
                resp.raise_for_status()
                data = resp.json()
                REPORTS_GENERATED.labels(framework=framework).inc()
                logger.info("Report generated: framework=%s events=%d path=%s",
                            framework, data.get("total_events", 0), data.get("report_path", ""))
            except Exception as exc:
                REPORTS_FAILED.labels(framework=framework).inc()
                logger.error("Failed to generate %s report: %s", framework, exc)

    def close(self):
        self._session.close()


job_runner = ComplianceJobRunner()
