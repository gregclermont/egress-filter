#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["mitmproxy"]
# ///
"""Simple mitmproxy transparent proxy that logs all connections."""

import json
import logging
import os
from mitmproxy import http, ctx

# Mitmproxy debug log (separate file, configure first)
MITMPROXY_LOG_FILE = os.environ.get("MITMPROXY_LOG_FILE", "/tmp/mitmproxy.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(name)s %(message)s',
    handlers=[
        logging.FileHandler(MITMPROXY_LOG_FILE),
        logging.StreamHandler()
    ]
)

# Our custom log (fully controlled, configure after basicConfig)
LOG_FILE = os.environ.get("PROXY_LOG_FILE", "/tmp/proxy.log")
logger = logging.getLogger("proxy")
logger.setLevel(logging.INFO)
logger.propagate = False  # Don't send to root logger
logger.handlers.clear()  # Remove any existing handlers
_file_handler = logging.FileHandler(LOG_FILE)
_file_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
logger.addHandler(_file_handler)


class ConnectionLogger:
    def load(self, loader):
        loader.add_option(
            name="config_file",
            typespec=str,
            default="config.json",
            help="Path to config file",
        )

    def running(self):
        logger.info(f"Proxy started in transparent mode, logging to {LOG_FILE}")

    def request(self, flow: http.HTTPFlow) -> None:
        logger.info(f"REQUEST: {flow.request.method} {flow.request.pretty_url}")

    def response(self, flow: http.HTTPFlow) -> None:
        logger.info(f"RESPONSE: {flow.request.method} {flow.request.pretty_url} -> {flow.response.status_code}")


addons = [ConnectionLogger()]

if __name__ == "__main__":
    from mitmproxy.tools.main import mitmdump
    mitmdump(["-s", __file__, "--mode", "transparent", "--showhost", "--set", "block_global=false"])
