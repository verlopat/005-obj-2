"""Blockchain Logger service entry point."""
import logging
import signal
import sys

from prometheus_client import start_http_server

from config import config
from worker import worker

logging.basicConfig(
    level=getattr(logging, config.log_level),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def _shutdown(signum, _frame):
    logger.info("Signal %d received — shutting down", signum)
    worker.stop()
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)
    logger.info("Starting blockchain-logger")
    start_http_server(config.metrics_port)
    logger.info("Prometheus metrics on :%d", config.metrics_port)
    worker.start()
    signal.pause()
