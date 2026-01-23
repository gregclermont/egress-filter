"""Logging configuration and connection event logging."""

import json
import logging
import os
from datetime import datetime, timezone

# Configuration from environment
LOG_FILE = os.environ.get("PROXY_LOG_FILE", "/tmp/proxy.log")
CONNECTIONS_FILE = os.environ.get("CONNECTIONS_FILE", "/tmp/connections.jsonl")
MITMPROXY_LOG_FILE = os.environ.get("MITMPROXY_LOG_FILE", "/tmp/mitmproxy.log")
VERBOSE = os.environ.get("VERBOSE", "0") == "1"

# Module-level state (initialized by init_logging)
logger: logging.Logger = None
_conn_file = None


def init_logging() -> logging.Logger:
    """Initialize logging. Returns the main logger."""
    global logger, _conn_file

    # Operational logger (human-readable)
    logger = logging.getLogger("egress_proxy")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.handlers.clear()
    handler = logging.FileHandler(LOG_FILE)
    handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    logger.addHandler(handler)

    # Connection events file (JSONL format, line-buffered)
    _conn_file = open(CONNECTIONS_FILE, "a", buffering=1)

    # Configure mitmproxy's internal logging (only in verbose mode)
    if VERBOSE:
        mitmproxy_handler = logging.FileHandler(MITMPROXY_LOG_FILE)
        mitmproxy_handler.setFormatter(logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s'))
        for mlog_name in ["mitmproxy", "mitmproxy.proxy", "mitmproxy.options"]:
            mlog = logging.getLogger(mlog_name)
            mlog.setLevel(logging.DEBUG)
            mlog.addHandler(mitmproxy_handler)

    return logger


def close_logging():
    """Close logging resources."""
    global _conn_file
    if _conn_file:
        _conn_file.close()
        _conn_file = None


def log_connection(**kwargs) -> None:
    """Log a connection event as JSONL (pid and src_port at end for readability)."""
    if not _conn_file:
        return
    # Extract fields we want at the end
    pid = kwargs.pop("pid", None)
    src_port = kwargs.pop("src_port", None)
    # Build event with ts first, then remaining fields, then pid/src_port at end
    event = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds")}
    event.update(kwargs)
    if src_port is not None:
        event["src_port"] = src_port
    if pid is not None:
        event["pid"] = pid
    _conn_file.write(json.dumps(event, separators=(",", ":")) + "\n")
