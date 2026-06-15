"""Compliance Scheduler — APScheduler-based job runner for automated compliance reports."""
import logging
import signal
import sys

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

from config import config
from jobs import generate_daily_reports, generate_weekly_reports, run_integrity_spot_check

logging.basicConfig(level=getattr(logging, config.log_level),
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

scheduler = BlockingScheduler(timezone="UTC")

def handle_shutdown(signum, frame):
    logger.info("Shutting down scheduler")
    scheduler.shutdown(wait=False)
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    scheduler.add_job(
        generate_daily_reports,
        CronTrigger(hour=config.schedule_daily_hour, minute=0),
        id="daily_compliance_reports",
        name="Daily Compliance Reports",
        max_instances=1,
        misfire_grace_time=3600,
    )
    scheduler.add_job(
        generate_weekly_reports,
        CronTrigger(day_of_week=config.schedule_weekly_day, hour=3, minute=0),
        id="weekly_compliance_reports",
        name="Weekly Compliance Reports",
        max_instances=1,
        misfire_grace_time=7200,
    )
    scheduler.add_job(
        run_integrity_spot_check,
        CronTrigger(minute="*/30"),
        id="integrity_spot_check",
        name="Integrity Spot Check",
        max_instances=1,
    )

    logger.info("Compliance scheduler started with %d jobs", len(scheduler.get_jobs()))
    scheduler.start()
