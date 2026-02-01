"""Protocol handlers."""

import functools
import traceback

from .. import logging as proxy_logging


def log_errors(func):
    """Decorator to log exceptions with full traceback before re-raising."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            proxy_logging.logger.error(f"{func.__name__} error: {e}")
            proxy_logging.logger.error(traceback.format_exc())
            raise
    return wrapper


from .mitmproxy import MitmproxyAddon
from .nfqueue import NfqueueHandler

__all__ = ["MitmproxyAddon", "NfqueueHandler", "log_errors"]
