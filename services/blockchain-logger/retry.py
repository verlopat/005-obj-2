"""Exponential backoff retry decorator with full jitter."""
import functools
import logging
import random
import time
from typing import Callable, Optional, Tuple, Type

logger = logging.getLogger(__name__)


def exponential_backoff(
    max_retries: int = 5,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    on_retry: Optional[Callable] = None,
):
    """Retry with exponential backoff + full jitter on the specified exceptions."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt == max_retries:
                        logger.error("%s failed after %d attempts: %s", func.__name__, max_retries, exc)
                        raise
                    cap = min(base_delay * (2 ** attempt), max_delay)
                    jitter = random.uniform(0, cap)
                    logger.warning("%s attempt %d/%d failed: %s — retrying in %.2fs",
                                   func.__name__, attempt + 1, max_retries, exc, jitter)
                    if on_retry:
                        on_retry(attempt, exc)
                    time.sleep(jitter)
            raise last_exc
        return wrapper
    return decorator
