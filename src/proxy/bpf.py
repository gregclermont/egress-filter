"""BPF program management and PID tracking."""

import ctypes
from pathlib import Path

import tinybpf

from . import logging as proxy_logging
from .utils import ip_to_int, IPPROTO_TCP


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
        # Conntrack reverser for NAT source-port mangling (created in setup()).
        self.conntrack = None

    def setup(self):
        """Load and attach BPF programs."""
        proxy_logging.logger.info(f"Loading BPF from {self.bpf_path}")
        self.bpf_obj = tinybpf.load(self.bpf_path)
        self.bpf_obj.__enter__()

        # Root cgroup - for IPv6 blocking only (cgroups are orthogonal to network namespaces)
        root_cgroup = "/sys/fs/cgroup"

        # TCP tracking: kprobe/tcp_connect
        # Note: cgroup/connect4 can't be used because at connect() time the kernel
        # hasn't assigned the ephemeral source port yet (src_port=0). The kprobe
        # fires later in the connection sequence with valid src_port.
        self.bpf_links.append(self.bpf_obj.program("kprobe_tcp_connect").attach_kprobe("tcp_connect"))

        # UDP tracking: kprobe (cgroup hooks don't work for connected UDP - see BPF comments)
        self.bpf_links.append(self.bpf_obj.program("kprobe_udp_sendmsg").attach_kprobe("udp_sendmsg"))

        # IPv6 blocking: cgroup hooks
        self.bpf_links.append(self.bpf_obj.program("block_connect6").attach_cgroup(root_cgroup))
        self.bpf_links.append(self.bpf_obj.program("block_sendmsg6").attach_cgroup(root_cgroup))

        # Raw socket blocking: cgroup/sock_create hook
        # Blocks SOCK_RAW and AF_PACKET to prevent iptables bypass
        self.bpf_links.append(self.bpf_obj.program("block_raw_sockets").attach_cgroup(root_cgroup))

        self.map_v4 = self.bpf_obj.maps["conn_to_pid_v4"].typed(key=ConnKeyV4, value=int)

        # NAT reversal for the transparent-proxy miss path (fail-safe if the
        # library is unavailable).
        from .conntrack import ConntrackReverser
        self.conntrack = ConntrackReverser()

        proxy_logging.logger.info("BPF loaded and attached")

    def cleanup(self):
        """Cleanup BPF resources."""
        proxy_logging.logger.info("Cleaning up BPF...")
        if self.conntrack:
            self.conntrack.close()
            self.conntrack = None
        for link in self.bpf_links:
            try:
                link.destroy()
            except Exception as e:
                proxy_logging.logger.warning(f"Error destroying BPF link: {e}")
        self.bpf_links.clear()
        if self.bpf_obj:
            self.bpf_obj.__exit__(None, None, None)

    def lookup_pid(self, dst_ip: str, src_port: int, dst_port: int, protocol: int = IPPROTO_TCP) -> int | None:
        """Look up PID from BPF map by 4-tuple."""
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

    def lookup_pid_nat_aware(
        self,
        dst_ip: str,
        dst_port: int,
        peername: tuple[str, int] | None,
        protocol: int = IPPROTO_TCP,
    ) -> int | None:
        """Look up PID for a transparently-proxied connection, reversing NAT.

        The kprobe records the original (pre-NAT) source port, but iptables
        REDIRECT can remap the source port under load, so `peername` (what the
        proxy sees) may not match. We first try the port the proxy sees; on a
        miss we ask conntrack for the original source port and retry.

        Args:
            dst_ip, dst_port: original destination (from SO_ORIGINAL_DST).
            peername: accepted socket's peer address (client_ip, src_port).
        """
        src_port = peername[1] if peername else 0
        pid = self.lookup_pid(dst_ip, src_port, dst_port, protocol)
        if pid is not None:
            return pid

        # Miss: the source port was likely NAT-remapped. Recover the original
        # from conntrack (identified by client address + original destination).
        if self.conntrack and peername:
            orig_port = self.conntrack.original_src_port(
                client=peername, orig_dst=(dst_ip, dst_port), protocol=protocol
            )
            if orig_port is not None and orig_port != src_port:
                return self.lookup_pid(dst_ip, orig_port, dst_port, protocol)
        return None
