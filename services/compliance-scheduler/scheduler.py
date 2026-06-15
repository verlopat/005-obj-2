"""APScheduler-based compliance report scheduler."""
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

import requests
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
from prometheus_client import Counter, start_http_server

from config import config

logger = logging.getLogger(__name__)
REPORTS_GENERATED = Counter("scheduler_reports_generated_total", "Reports generated", ["framework", "period"])
REPORTS_FAILED    = Counter("scheduler_reports_failed_total",    "Report generation failures", ["framework"])


class ComplianceScheduler:
    def __init__(self):
        self._scheduler = BlockingScheduler(timezone="UTC")
        self._output_dir = Path(config.report_output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._session = requests.Session()
        self._session.timeout = 120

    def _fetch_and_save(
        self,
        framework: str,
        start: str,
        end: str,
        period_label: str,
        fmt: str = "json",
    ) -> None:
        url = f"{config.audit_api_url}/api/v1/reports"
        params = {"framework": framework, "start": start, "end": end, "fmt": fmt}
        try:
            resp = self._session.get(url, params=params)
            resp.raise_for_status()
            ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
            fname = self._output_dir / f"{framework}_{period_label}_{ts}.{fmt}"
            fname.write_bytes(resp.content)
            logger.info("Saved %s report: %s", framework, fname)
            REPORTS_GENERATED.labels(framework=framework, period=period_label).inc()
        except Exception as exc:
            logger.error("Failed to generate %s report: %s", framework, exc)
            REPORTS_FAILED.labels(framework=framework).inc()

    def _daily_job(self):
        end   = datetime.utcnow()
        start = end - timedelta(days=1)
        for fw in config.framework_list:
            self._fetch_and_save(fw, start.isoformat() + "Z", end.isoformat() + "Z", "daily", "json")
            self._fetch_and_save(fw, start.isoformat() + "Z", end.isoformat() + "Z", "daily", "csv")

    def _weekly_job(self):
        end   = datetime.utcnow()
        start = end - timedelta(weeks=1)
        for fw in config.framework_list:
            self._fetch_and_save(fw, start.isoformat() + "Z", end.isoformat() + "Z", "weekly", "json")
            self._fetch_and_save(fw, start.isoformat() + "Z", end.isoformat() + "Z", "weekly", "csv")

    def _cleanup_old_reports(self):
        cutoff = datetime.utcnow() - timedelta(days=config.report_retention_days)
        for f in self._output_dir.glob("*.json"):
            if datetime.utcfromtimestamp(f.stat().st_mtime) < cutoff:
                f.unlink()
                logger.info("Pruned old report: %s", f.name)

    def run(self):
        daily_h, daily_m = config.schedule_daily.split(":")
        weekly_parts = config.schedule_weekly.split()
        weekly_dow = weekly_parts[0]
        weekly_h, weekly_m = weekly_parts[1].split(":")

        self._scheduler.add_job(self._daily_job,  CronTrigger(hour=daily_h,  minute=daily_m),  id="daily")
        self._scheduler.add_job(self._weekly_job, CronTrigger(day_of_week=weekly_dow, hour=weekly_h, minute=weekly_m), id="weekly")
        self._scheduler.add_job(self._cleanup_old_reports, CronTrigger(hour=4, minute=0), id="cleanup")
        logger.info("Compliance scheduler started (daily@%s, weekly@%s)",
                    config.schedule_daily, config.schedule_weekly)
        self._scheduler.start()
