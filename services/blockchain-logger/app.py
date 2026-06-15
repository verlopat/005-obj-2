"""Blockchain Logger service entry point."""
import logging
import signal
import sys
from prometheus_client import start_http_server
from config import config
from worker import worker

logging.basicConfig(level=getattr(logging, config.log_level),
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

def handle_shutdown(signum, frame):
    logger.info("Signal %d received — shutting down", signum)
    worker.stop()
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)
    logger.info("Starting blockchain-logger service")
    start_http_server(config.metrics_port)
    logger.info("Prometheus metrics on port %d", config.metrics_port)
    worker.start()
    signal.pause()
