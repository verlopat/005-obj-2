"""Compliance Scheduler - APScheduler-driven report generation."""
import logging
import signal
import sys

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
from prometheus_client import start_http_server

from config import config
from jobs import job_runner

logging.basicConfig(level=getattr(logging, config.log_level),
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def handle_shutdown(signum, frame):
    logger.info("Signal %d - shutting down scheduler", signum)
    job_runner.close()
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    logger.info("Starting compliance-scheduler")
    start_http_server(config.metrics_port)

    scheduler = BlockingScheduler(timezone="UTC")

    scheduler.add_job(
        job_runner.run_daily_report,
        CronTrigger(hour=config.schedule_daily_hour, minute=0),
        id="daily_report",
        name="Daily compliance report",
        replace_existing=True,
    )
    scheduler.add_job(
        job_runner.run_weekly_report,
        CronTrigger(day_of_week=config.schedule_weekly_day, hour=config.schedule_daily_hour + 1),
        id="weekly_report",
        name="Weekly compliance report",
        replace_existing=True,
    )
    scheduler.add_job(
        job_runner.run_monthly_report,
        CronTrigger(day=config.schedule_monthly_day, hour=config.schedule_daily_hour + 2),
        id="monthly_report",
        name="Monthly compliance report",
        replace_existing=True,
    )

    logger.info("Scheduler started with jobs: daily, weekly, monthly")
    scheduler.start()
