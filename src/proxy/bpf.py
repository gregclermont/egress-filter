"""BPF program management and PID tracking."""

import ctypes
from pathlib import Path

import tinybpf

from . import logging as proxy_logging
from .utils import get_cgroup, ip_to_int, IPPROTO_TCP


class ConnKeyV4(ctypes.Structure):
    """BPF map key structure for IPv4 connections."""
    _pack_ = 1
    _fields_ = [
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
    ]


class BPFState:
    """BPF program state and PID lookup."""

    def __init__(self, bpf_path: str | None = None):
        # Default BPF path relative to this file (src/proxy/ -> dist/bpf/)
        if bpf_path is None:
            repo_root = Path(__file__).parent.parent.parent.resolve()
            bpf_path = str(repo_root / "dist" / "bpf" / "conn_tracker.bpf.o")
        self.bpf_path = bpf_path
        self.bpf_obj = None
        self.bpf_links = []
        self.map_v4 = None
        # DNS 4-tuple cache: (src_port, txid) -> (pid, dst_ip, dst_port)
        # Populated by nfqueue (before NAT), consumed by mitmproxy (after NAT)
        self.dns_cache = {}

    def setup(self):
        """Load and attach BPF programs."""
        cgroup = get_cgroup()
        proxy_logging.logger.info(f"Attaching to cgroup {cgroup}")

        proxy_logging.logger.info(f"Loading BPF from {self.bpf_path}")
        self.bpf_obj = tinybpf.load(self.bpf_path)
        self.bpf_obj.__enter__()

        # IPv4 tracking
        self.bpf_links.append(self.bpf_obj.program("handle_sockops").attach_cgroup(cgroup))
        self.bpf_links.append(self.bpf_obj.program("handle_sendmsg4").attach_cgroup(cgroup))
        self.bpf_links.append(self.bpf_obj.program("kprobe_udp_sendmsg").attach_kprobe("udp_sendmsg"))

        # IPv6 blocking (forces apps to use IPv4, which goes through transparent proxy)
        self.bpf_links.append(self.bpf_obj.program("block_connect6").attach_cgroup(cgroup))
        self.bpf_links.append(self.bpf_obj.program("block_sendmsg6").attach_cgroup(cgroup))

        self.map_v4 = self.bpf_obj.maps["conn_to_pid_v4"].typed(key=ConnKeyV4, value=int)

        proxy_logging.logger.info("BPF loaded and attached")

    def cleanup(self):
        """Cleanup BPF resources."""
        proxy_logging.logger.info("Cleaning up BPF...")
        for link in self.bpf_links:
            try:
                link.destroy()
            except Exception as e:
                proxy_logging.logger.warning(f"Error destroying BPF link: {e}")
        self.bpf_links.clear()
        if self.bpf_obj:
            self.bpf_obj.__exit__(None, None, None)

    def lookup_pid(self, dst_ip: str, src_port: int, dst_port: int, protocol: int = IPPROTO_TCP) -> int | None:
        """Look up PID from BPF map."""
        if not self.map_v4:
            return None
        try:
            key = ConnKeyV4(
                dst_ip=ip_to_int(dst_ip),
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
            )
            return self.map_v4.get(key)
        except Exception:
            return None
