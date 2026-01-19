#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["mitmproxy"]
# ///
"""Simple mitmproxy transparent proxy that logs all connections."""

import json
import logging
import os
from mitmproxy import http, tcp, ctx

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
        # HTTP/HTTPS request (same handler for both)
        src_port = flow.client_conn.peername[1] if flow.client_conn.peername else 0
        dst_ip, dst_port = flow.server_conn.address if flow.server_conn.address else ("unknown", 0)
        url = flow.request.pretty_url
        logger.info(f"HTTP src_port={src_port} dst={dst_ip}:{dst_port} url={url}")

    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        # Non-HTTP TCP connection
        src_port = flow.client_conn.peername[1] if flow.client_conn.peername else 0
        dst_ip, dst_port = flow.server_conn.address if flow.server_conn.address else ("unknown", 0)
        logger.info(f"TCP src_port={src_port} dst={dst_ip}:{dst_port}")


addons = [ConnectionLogger()]

if __name__ == "__main__":
    from mitmproxy.tools.main import mitmdump
    mitmdump(["-s", __file__, "--mode", "transparent", "--showhost", "--set", "block_global=false"])
