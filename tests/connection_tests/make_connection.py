#!/usr/bin/env python3
"""Make a single network connection for testing.

Usage: make_connection.py <marker> <type> <target>

Types:
  http <url>          - HTTP GET request
  https <url>         - HTTPS GET request
  dns <name>          - DNS lookup
  udp <host:port>     - UDP packet (unconnected, sendto)
  udp_connected <host:port> - UDP packet (connected socket)
  tcp <host:port>     - TCP connect (IPv4)
  tcp6 <host:port>    - TCP connect (IPv6, expected to be blocked)

Outputs JSON result to stdout.
"""

import json
import socket
import sys


def make_http(url: str) -> dict:
    import urllib.request
    urllib.request.urlopen(url, timeout=5)
    return {"type": "http", "url": url}


def make_https(url: str) -> dict:
    import urllib.request
    import ssl
    # Allow self-signed certs for testing with mitmproxy
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    urllib.request.urlopen(url, timeout=5, context=ctx)
    return {"type": "https", "url": url}


def make_dns(name: str) -> dict:
    socket.gethostbyname(name)
    return {"type": "dns", "name": name}


def make_udp(target: str) -> dict:
    """Unconnected UDP: sendto() with destination in each call."""
    host, port = target.rsplit(":", 1)
    port = int(port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(b"test", (host, port))
    sock.close()
    return {"type": "udp", "host": host, "port": port}


def make_udp_connected(target: str) -> dict:
    """Connected UDP: connect() then send() without destination."""
    host, port = target.rsplit(":", 1)
    port = int(port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((host, port))
    sock.send(b"test")
    sock.close()
    return {"type": "udp_connected", "host": host, "port": port}


def make_tcp(target: str) -> dict:
    host, port = target.rsplit(":", 1)
    port = int(port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, port))
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass  # Connection attempt is enough for logging
    finally:
        sock.close()
    return {"type": "tcp", "host": host, "port": port}


def make_tcp6(target: str) -> dict:
    """TCP over IPv6 - should be blocked by ip6tables."""
    host, port = target.rsplit(":", 1)
    port = int(port)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect((host, port))
    except (socket.timeout, ConnectionRefusedError, OSError, socket.error):
        pass  # Expected to fail (blocked)
    finally:
        sock.close()
    return {"type": "tcp6", "host": host, "port": port}


HANDLERS = {
    "http": make_http,
    "https": make_https,
    "dns": make_dns,
    "udp": make_udp,
    "udp_connected": make_udp_connected,
    "tcp": make_tcp,
    "tcp6": make_tcp6,
}


def main():
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        sys.exit(1)

    marker = sys.argv[1]
    conn_type = sys.argv[2]
    target = sys.argv[3]

    if conn_type not in HANDLERS:
        print(f"Unknown type: {conn_type}", file=sys.stderr)
        sys.exit(1)

    try:
        result = HANDLERS[conn_type](target)
        result["marker"] = marker
        result["success"] = True
    except Exception as e:
        result = {
            "marker": marker,
            "type": conn_type,
            "target": target,
            "success": False,
            "error": str(e),
        }

    print(json.dumps(result))


if __name__ == "__main__":
    main()
