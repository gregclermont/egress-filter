#!/usr/bin/env python3
"""Generate test connections to exercise all BPF code paths."""

import socket
import subprocess
import sys


def test_tcp_ipv4():
    """TCP IPv4 via handle_sockops AF_INET path."""
    print("Testing TCP IPv4...", end=" ", flush=True)
    try:
        result = subprocess.run(
            ["curl", "-4", "-s", "--max-time", "5", "http://example.com"],
            capture_output=True,
            timeout=10,
        )
        print("OK" if result.returncode == 0 else "FAILED")
        return result.returncode == 0
    except Exception as e:
        print(f"FAILED: {e}")
        return False


def test_tcp_ipv6():
    """TCP IPv6 via handle_sockops AF_INET6 native path."""
    print("Testing TCP IPv6...", end=" ", flush=True)
    try:
        result = subprocess.run(
            ["curl", "-6", "-s", "--max-time", "5", "http://example.com"],
            capture_output=True,
            timeout=10,
        )
        print("OK" if result.returncode == 0 else "SKIPPED (no IPv6)")
        return True  # Don't fail if no IPv6
    except Exception as e:
        print(f"SKIPPED: {e}")
        return True


def test_tcp_v4mapped():
    """TCP via handle_sockops AF_INET6 v4-mapped path."""
    print("Testing TCP v4-mapped...", end=" ", flush=True)
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(10)
        # Google DNS IPv4 as v4-mapped IPv6 (port 443 for HTTPS)
        s.connect(("::ffff:8.8.8.8", 443))
        port = s.getsockname()[1]
        s.close()
        print(f"OK (port {port})")
        return True
    except Exception as e:
        print(f"FAILED: {e}")
        return False


def test_udp_ipv4():
    """UDP IPv4 via handle_sendmsg4."""
    print("Testing UDP IPv4...", end=" ", flush=True)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        # Send DNS query to Google DNS
        s.sendto(b"\x00", ("8.8.8.8", 53))
        port = s.getsockname()[1]
        s.close()
        print(f"OK (port {port})")
        return True
    except Exception as e:
        print(f"FAILED: {e}")
        return False


def test_udp_ipv6():
    """UDP IPv6 via handle_sendmsg6 native path."""
    print("Testing UDP IPv6...", end=" ", flush=True)
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.settimeout(5)
        # Google's IPv6 DNS
        s.sendto(b"\x00", ("2001:4860:4860::8888", 53))
        port = s.getsockname()[1]
        s.close()
        print(f"OK (port {port})")
        return True
    except socket.gaierror:
        print("SKIPPED (no IPv6)")
        return True  # Don't fail if no IPv6
    except Exception as e:
        print(f"SKIPPED: {e}")
        return True


def test_udp_v4mapped():
    """UDP via handle_sendmsg6 v4-mapped path."""
    print("Testing UDP v4-mapped...", end=" ", flush=True)
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.settimeout(5)
        # Google DNS IPv4 as v4-mapped IPv6
        s.sendto(b"\x00", ("::ffff:8.8.8.8", 53))
        port = s.getsockname()[1]
        s.close()
        print(f"OK (port {port})")
        return True
    except Exception as e:
        print(f"FAILED: {e}")
        return False


def main():
    print("=== Testing all BPF code paths ===\n")

    results = [
        ("TCP IPv4 (sockops AF_INET)", test_tcp_ipv4()),
        ("TCP IPv6 (sockops AF_INET6)", test_tcp_ipv6()),
        ("TCP v4-mapped (sockops AF_INET6 mapped)", test_tcp_v4mapped()),
        ("UDP IPv4 (sendmsg4)", test_udp_ipv4()),
        ("UDP IPv6 (sendmsg6 native)", test_udp_ipv6()),
        ("UDP v4-mapped (sendmsg6 mapped)", test_udp_v4mapped()),
    ]

    print("\n=== Summary ===")
    failed = [name for name, ok in results if not ok]
    if failed:
        print(f"FAILED: {', '.join(failed)}")
        sys.exit(1)
    else:
        print("All tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
