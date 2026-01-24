#!/usr/bin/env python3
"""
Test raw socket capabilities and potential proxy bypass on GHA runners.

Tests:
1. Check capabilities (CAP_NET_RAW)
2. Try to create various raw socket types
3. Attempt to send packets that bypass iptables

Run with: sudo python3 test_raw_sockets.py
"""

import ctypes
import ctypes.util
import json
import os
import socket
import struct
import subprocess
import sys

# Protocol numbers
IPPROTO_RAW = 255
IPPROTO_TCP = 6
IPPROTO_ICMP = 1
ETH_P_IP = 0x0800
ETH_P_ALL = 0x0003

results = {}


def log(msg):
    print(f"[*] {msg}")


def log_result(test_name, success, details=None):
    results[test_name] = {"success": success, "details": details}
    status = "✓" if success else "✗"
    print(f"[{status}] {test_name}: {details or ''}")


def check_capabilities():
    """Check if CAP_NET_RAW is available."""
    log("Checking capabilities...")

    # Check current process capabilities
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("Cap"):
                    print(f"    {line.strip()}")
    except Exception as e:
        log(f"Failed to read capabilities: {e}")

    # Try to decode CapEff
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    cap_hex = int(line.split()[1], 16)
                    CAP_NET_RAW = 13
                    has_net_raw = bool(cap_hex & (1 << CAP_NET_RAW))
                    log_result("CAP_NET_RAW available", has_net_raw, f"CapEff=0x{cap_hex:x}")
                    return has_net_raw
    except Exception as e:
        log_result("CAP_NET_RAW available", False, str(e))
        return False


def test_sock_raw_icmp():
    """Test SOCK_RAW with ICMP (most commonly allowed)."""
    log("Testing SOCK_RAW with ICMP...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_ICMP)
        sock.close()
        log_result("SOCK_RAW + ICMP", True, "Socket created successfully")
        return True
    except PermissionError as e:
        log_result("SOCK_RAW + ICMP", False, f"Permission denied: {e}")
        return False
    except Exception as e:
        log_result("SOCK_RAW + ICMP", False, str(e))
        return False


def test_sock_raw_tcp():
    """Test SOCK_RAW with TCP."""
    log("Testing SOCK_RAW with TCP...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_TCP)
        sock.close()
        log_result("SOCK_RAW + TCP", True, "Socket created successfully")
        return True
    except PermissionError as e:
        log_result("SOCK_RAW + TCP", False, f"Permission denied: {e}")
        return False
    except Exception as e:
        log_result("SOCK_RAW + TCP", False, str(e))
        return False


def test_sock_raw_raw():
    """Test SOCK_RAW with IPPROTO_RAW (full IP header control)."""
    log("Testing SOCK_RAW with IPPROTO_RAW...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.close()
        log_result("SOCK_RAW + IPPROTO_RAW", True, "Socket created with IP_HDRINCL")
        return True
    except PermissionError as e:
        log_result("SOCK_RAW + IPPROTO_RAW", False, f"Permission denied: {e}")
        return False
    except Exception as e:
        log_result("SOCK_RAW + IPPROTO_RAW", False, str(e))
        return False


def test_af_packet():
    """Test AF_PACKET socket (bypasses IP layer entirely)."""
    log("Testing AF_PACKET...")
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock.close()
        log_result("AF_PACKET", True, "Socket created successfully - can bypass iptables!")
        return True
    except PermissionError as e:
        log_result("AF_PACKET", False, f"Permission denied: {e}")
        return False
    except Exception as e:
        log_result("AF_PACKET", False, str(e))
        return False


def get_default_interface():
    """Get the default network interface."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True
        )
        # Parse: "default via X.X.X.X dev eth0 ..."
        parts = result.stdout.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def build_ip_header(src_ip, dst_ip, payload_len, protocol=IPPROTO_TCP):
    """Build an IP header."""
    version_ihl = (4 << 4) | 5  # IPv4, 5 words (20 bytes)
    tos = 0
    total_len = 20 + payload_len
    identification = 54321
    flags_fragment = 0
    ttl = 64
    checksum = 0  # Will be filled by kernel or we calculate

    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_len,
        identification, flags_fragment,
        ttl, protocol, checksum,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip)
    )
    return header


def build_tcp_header(src_port, dst_port, seq=0, ack=0, flags=0x02):
    """Build a TCP header (SYN by default)."""
    data_offset = (5 << 4)  # 5 words, no options
    window = 65535
    checksum = 0  # Should calculate, but kernel might help
    urgent = 0

    header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port,
        seq, ack,
        data_offset, flags,
        window, checksum, urgent
    )
    return header


def test_raw_packet_send():
    """Try to send a raw packet to an external host."""
    log("Testing raw packet send (may bypass proxy)...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except Exception as e:
        log_result("Raw packet send", False, f"Cannot create socket: {e}")
        return False

    try:
        # Target: example.com:80 (well-known, stable)
        dst_ip = socket.gethostbyname("example.com")
        src_ip = "0.0.0.0"  # Kernel will fill

        # Build packet
        tcp_header = build_tcp_header(src_port=44444, dst_port=80, flags=0x02)  # SYN
        ip_header = build_ip_header(src_ip, dst_ip, len(tcp_header), IPPROTO_TCP)
        packet = ip_header + tcp_header

        # Try to send
        sock.sendto(packet, (dst_ip, 0))
        sock.close()

        log_result("Raw packet send", True, f"Sent raw SYN to {dst_ip}:80 - check if it bypassed proxy!")
        return True
    except Exception as e:
        log_result("Raw packet send", False, str(e))
        return False


def test_af_packet_send():
    """Try to send via AF_PACKET (complete iptables bypass)."""
    log("Testing AF_PACKET send (bypasses iptables)...")

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    except Exception as e:
        log_result("AF_PACKET send", False, f"Cannot create socket: {e}")
        return False

    try:
        iface = get_default_interface()
        sock.bind((iface, 0))

        # We'd need to build full Ethernet frame + IP + TCP
        # This is complex, just test that we CAN send
        log_result("AF_PACKET send", True, f"AF_PACKET socket bound to {iface} - CAN bypass iptables")
        sock.close()
        return True
    except Exception as e:
        log_result("AF_PACKET send", False, str(e))
        return False


def check_iptables_raw():
    """Check if there are any iptables rules that might catch raw sockets."""
    log("Checking iptables raw table...")
    try:
        result = subprocess.run(
            ["iptables", "-t", "raw", "-L", "-v", "-n"],
            capture_output=True, text=True
        )
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
    except Exception as e:
        log(f"Failed to check iptables: {e}")


def main():
    log("=" * 60)
    log("Raw Socket Bypass Test")
    log("=" * 60)

    if os.geteuid() != 0:
        log("WARNING: Not running as root, some tests may fail")

    print()

    # Capability check
    check_capabilities()
    print()

    # Socket creation tests
    test_sock_raw_icmp()
    test_sock_raw_tcp()
    test_sock_raw_raw()
    test_af_packet()
    print()

    # Actual send tests
    test_raw_packet_send()
    test_af_packet_send()
    print()

    # iptables check
    check_iptables_raw()
    print()

    # Summary
    log("=" * 60)
    log("Summary")
    log("=" * 60)
    print(json.dumps(results, indent=2))

    # Key finding
    if results.get("AF_PACKET", {}).get("success"):
        log("")
        log("⚠️  AF_PACKET available - complete iptables bypass possible!")
        log("   Attacker can craft packets at Ethernet layer, bypassing all our controls.")


if __name__ == "__main__":
    main()
