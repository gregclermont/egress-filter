#!/usr/bin/env python3
"""
eBPF-based connection-to-PID tracker for egress firewall.

Loads port_tracker BPF programs and provides lookup of PIDs by connection tuple.
"""

import argparse
import ctypes
import ipaddress
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import tinybpf

# Initialize with system libbpf if bundled isn't available
for libbpf_path in ["/usr/lib/x86_64-linux-gnu/libbpf.so.1", "/usr/lib/libbpf.so.1"]:
    if Path(libbpf_path).exists():
        tinybpf.init(libbpf_path)
        break

IPPROTO_TCP = 6
IPPROTO_UDP = 17

BPF_PATH = Path(__file__).parent / "src" / "bpf" / "port_tracker.bpf.o"


def get_self_cgroup() -> str:
    """Get the cgroup path for the current process."""
    cgroup_info = Path("/proc/self/cgroup").read_text().strip()
    # Format: "0::/system.slice/foo.service"
    cgroup_rel = cgroup_info.split(":")[-1]
    return f"/sys/fs/cgroup{cgroup_rel}"


DEFAULT_CGROUP = get_self_cgroup()


class ConnKeyV4(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
    ]


class ConnKeyV6(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("dst_ip", ctypes.c_uint32 * 4),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
    ]


def ip_to_int(ip_str: str) -> int | tuple[int, int, int, int]:
    """Convert IP string to integer(s) for map lookup."""
    addr = ipaddress.ip_address(ip_str)
    if isinstance(addr, ipaddress.IPv4Address):
        return socket.htonl(int(addr))
    else:
        packed = addr.packed
        return (
            int.from_bytes(packed[0:4], "big"),
            int.from_bytes(packed[4:8], "big"),
            int.from_bytes(packed[8:12], "big"),
            int.from_bytes(packed[12:16], "big"),
        )


def format_ipv4(ip_int: int) -> str:
    """Format integer IP to dotted string."""
    ip_host = socket.ntohl(ip_int)
    return str(ipaddress.IPv4Address(ip_host))


def format_ipv6(ip_ints: tuple[int, int, int, int]) -> str:
    """Format IPv6 address from 4 32-bit ints."""
    packed = b"".join(i.to_bytes(4, "big") for i in ip_ints)
    return str(ipaddress.IPv6Address(packed))


def protocol_name(proto: int) -> str:
    return "TCP" if proto == IPPROTO_TCP else "UDP" if proto == IPPROTO_UDP else str(proto)


def get_comm(pid: int) -> str:
    """Get command name from /proc."""
    try:
        return Path(f"/proc/{pid}/comm").read_text().strip()
    except (OSError, FileNotFoundError):
        return "?"


class ConnectionTracker:
    """Manages BPF programs and provides connection-to-PID lookups."""

    def __init__(self, bpf_path: Path, cgroup_path: str):
        self.bpf_path = bpf_path
        self.cgroup_path = cgroup_path
        self._obj = None
        self._links = []  # Must keep links alive to maintain attachment
        self._map_v4 = None
        self._map_v6 = None

    def __enter__(self):
        self._obj = tinybpf.load(str(self.bpf_path))
        self._obj.__enter__()

        # Store links to keep attachments alive (they detach when garbage collected)
        self._links.append(self._obj.program("handle_sockops").attach_cgroup(self.cgroup_path))
        self._links.append(self._obj.program("handle_sendmsg4").attach_cgroup(self.cgroup_path))
        self._links.append(self._obj.program("handle_sendmsg6").attach_cgroup(self.cgroup_path))

        self._map_v4 = self._obj.maps["conn_to_pid_v4"].typed(key=ConnKeyV4, value=ctypes.c_uint32)
        self._map_v6 = self._obj.maps["conn_to_pid_v6"].typed(key=ConnKeyV6, value=ctypes.c_uint32)

        return self

    def __exit__(self, *args):
        # Destroy links first (detach programs)
        for link in self._links:
            link.destroy()
        self._links.clear()
        if self._obj:
            self._obj.__exit__(*args)

    def lookup(
        self, dst_ip: str, src_port: int, dst_port: int, protocol: int = IPPROTO_TCP
    ) -> int | None:
        """Look up PID info for a connection tuple."""
        addr = ipaddress.ip_address(dst_ip)

        if isinstance(addr, ipaddress.IPv4Address):
            key = ConnKeyV4(
                dst_ip=socket.htonl(int(addr)),
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
            )
            return self._map_v4.get(key)
        else:
            packed = addr.packed
            ip_ints = (ctypes.c_uint32 * 4)(
                int.from_bytes(packed[0:4], "big"),
                int.from_bytes(packed[4:8], "big"),
                int.from_bytes(packed[8:12], "big"),
                int.from_bytes(packed[12:16], "big"),
            )
            key = ConnKeyV6(
                dst_ip=ip_ints,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
            )
            return self._map_v6.get(key)

    def dump_all(self):
        """Print all tracked connections."""
        print("IPv4 connections:")
        for key, pid in self._map_v4.items():
            print(
                f"  {format_ipv4(key.dst_ip)}:{key.dst_port} <- :{key.src_port} "
                f"[{protocol_name(key.protocol)}] PID={pid} ({get_comm(pid)})"
            )

        print("\nIPv6 connections:")
        for key, pid in self._map_v6.items():
            ip_tuple = tuple(key.dst_ip[i] for i in range(4))
            print(
                f"  [{format_ipv6(ip_tuple)}]:{key.dst_port} <- :{key.src_port} "
                f"[{protocol_name(key.protocol)}] PID={pid} ({get_comm(pid)})"
            )


def cmd_run(args):
    """Run the tracker and periodically dump connections."""
    print(f"Loading BPF from {args.bpf}")
    print(f"Attaching to cgroup {args.cgroup}")

    running = True

    def handle_signal(sig, frame):
        nonlocal running
        print("\nShutting down...")
        running = False

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    with ConnectionTracker(Path(args.bpf), args.cgroup) as tracker:
        print("Tracker active. Press Ctrl+C to stop.\n")
        while running:
            tracker.dump_all()
            print()
            time.sleep(args.interval)


def cmd_lookup(args):
    """Look up a single connection."""
    protocol = IPPROTO_TCP if args.protocol.lower() == "tcp" else IPPROTO_UDP

    with ConnectionTracker(Path(args.bpf), args.cgroup) as tracker:
        pid = tracker.lookup(args.dst_ip, args.src_port, args.dst_port, protocol)
        if pid:
            print(f"PID: {pid}")
            print(f"Command: {get_comm(pid)}")
        else:
            print("Connection not found in tracker")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="eBPF connection-to-PID tracker")
    parser.add_argument(
        "--bpf", default=str(BPF_PATH), help="Path to compiled BPF object"
    )
    parser.add_argument(
        "--cgroup", default=DEFAULT_CGROUP, help="Cgroup v2 path to attach to"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run tracker and dump connections")
    run_parser.add_argument(
        "--interval", type=float, default=2.0, help="Dump interval in seconds"
    )
    run_parser.set_defaults(func=cmd_run)

    lookup_parser = subparsers.add_parser("lookup", help="Look up a single connection")
    lookup_parser.add_argument("dst_ip", help="Destination IP address")
    lookup_parser.add_argument("src_port", type=int, help="Source port")
    lookup_parser.add_argument("dst_port", type=int, help="Destination port")
    lookup_parser.add_argument(
        "--protocol", "-p", default="tcp", choices=["tcp", "udp"], help="Protocol"
    )
    lookup_parser.set_defaults(func=cmd_lookup)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
