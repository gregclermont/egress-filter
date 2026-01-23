"""Utility functions."""

import socket
import struct
from pathlib import Path

# Protocol constants
IPPROTO_TCP = 6
IPPROTO_UDP = 17


def ip_to_int(ip_str: str) -> int:
    """Convert IP string to integer matching BPF map key format.

    BPF stores sin_addr.s_addr (network byte order) directly into a u32.
    On little-endian machines (x86), this means the bytes are stored as-is
    but interpreted as little-endian. We must match that interpretation.

    Handles IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) by extracting the IPv4 part.
    """
    # Handle IPv4-mapped IPv6 addresses
    if ip_str.startswith("::ffff:"):
        ip_str = ip_str[7:]  # Extract the IPv4 portion
    # Use little-endian to match how BPF interprets the network-order bytes
    return struct.unpack("<I", socket.inet_aton(ip_str))[0]


def get_cgroup() -> str:
    """Get the cgroup path for the current process."""
    cgroup_info = Path("/proc/self/cgroup").read_text().strip()
    cgroup_rel = cgroup_info.split(":")[-1]
    return f"/sys/fs/cgroup{cgroup_rel}"
