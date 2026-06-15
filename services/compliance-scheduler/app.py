"""Compliance Scheduler entry point."""
import logging

from prometheus_client import start_http_server

from config import config
from scheduler import ComplianceScheduler

logging.basicConfig(level=getattr(logging, config.log_level),
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")

if __name__ == "__main__":
    start_http_server(config.metrics_port)
    ComplianceScheduler().run()
