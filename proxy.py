#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["mitmproxy"]
# ///
"""Simple mitmproxy transparent proxy that logs all connections."""

import json
import logging
from mitmproxy import http, ctx

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
logger = logging.getLogger(__name__)


class ConnectionLogger:
    def load(self, loader):
        loader.add_option(
            name="config_file",
            typespec=str,
            default="config.json",
            help="Path to config file",
        )

    def running(self):
        logger.info("Proxy started in transparent mode")

    def request(self, flow: http.HTTPFlow) -> None:
        logger.info(f"HTTP: {flow.request.method} {flow.request.pretty_url}")

    def response(self, flow: http.HTTPFlow) -> None:
        logger.info(f"HTTP: {flow.request.method} {flow.request.pretty_url} -> {flow.response.status_code}")


addons = [ConnectionLogger()]

if __name__ == "__main__":
    from mitmproxy.tools.main import mitmdump
    mitmdump(["-s", __file__, "--mode", "transparent", "--showhost", "--set", "block_global=false"])
