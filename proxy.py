#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["mitmproxy", "tinybpf==0.1.0"]
#
# [[tool.uv.index]]
# name = "tinybpf"
# url = "https://gregclermont.github.io/tinybpf"
#
# [tool.uv.sources]
# tinybpf = { index = "tinybpf" }
# ///
"""Simple mitmproxy transparent proxy that logs all connections with PID tracking."""

import ctypes
import logging
import os
import socket
import ipaddress
from pathlib import Path
from mitmproxy import http, tcp, dns, ctx
import tinybpf

IPPROTO_TCP = 6
IPPROTO_UDP = 17

# BPF map key structures (must match BPF program)
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

class DnsKey(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("src_port", ctypes.c_uint16),
    ]

def get_comm(pid: int) -> str:
    """Get command name from /proc."""
    try:
        return Path(f"/proc/{pid}/comm").read_text().strip()
    except (OSError, FileNotFoundError):
        return "?"

def get_cgroup() -> str:
    """Get the cgroup path for the current process."""
    cgroup_info = Path("/proc/self/cgroup").read_text().strip()
    cgroup_rel = cgroup_info.split(":")[-1]
    return f"/sys/fs/cgroup{cgroup_rel}"

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
    def __init__(self):
        self._bpf_obj = None
        self._bpf_links = []
        self._map_v4 = None
        self._map_v6 = None
        self._map_dns = None

    def load(self, loader):
        loader.add_option(
            name="bpf_path",
            typespec=str,
            default="src/bpf/port_tracker.bpf.o",
            help="Path to compiled BPF object",
        )

    def running(self):
        # Load BPF and attach to cgroup
        bpf_path = ctx.options.bpf_path
        cgroup = get_cgroup()

        logger.info(f"Loading BPF from {bpf_path}")
        logger.info(f"Attaching to cgroup {cgroup}")

        self._bpf_obj = tinybpf.load(bpf_path)
        self._bpf_obj.__enter__()

        self._bpf_links.append(self._bpf_obj.program("handle_sockops").attach_cgroup(cgroup))
        self._bpf_links.append(self._bpf_obj.program("handle_sendmsg4").attach_cgroup(cgroup))
        self._bpf_links.append(self._bpf_obj.program("handle_sendmsg6").attach_cgroup(cgroup))
        # kprobe for UDP - works for loopback addresses unlike cgroup hooks
        self._bpf_links.append(self._bpf_obj.program("kprobe_udp_sendmsg").attach_kprobe("udp_sendmsg"))

        self._map_v4 = self._bpf_obj.maps["conn_to_pid_v4"].typed(key=ConnKeyV4, value=int)
        self._map_v6 = self._bpf_obj.maps["conn_to_pid_v6"].typed(key=ConnKeyV6, value=int)
        self._map_dns = self._bpf_obj.maps["dns_to_pid"].typed(key=DnsKey, value=int)

        logger.info(f"Proxy started in transparent mode, logging to {LOG_FILE}")

    def done(self):
        # Dump map contents for debugging
        self._dump_maps()
        # Cleanup BPF
        for link in self._bpf_links:
            link.destroy()
        self._bpf_links.clear()
        if self._bpf_obj:
            self._bpf_obj.__exit__(None, None, None)

    def _dump_maps(self):
        """Dump all map entries for debugging."""
        logger.info("=== BPF Map Dump ===")
        if self._map_v4:
            for key, pid in self._map_v4.items():
                dst_ip = socket.ntohl(key.dst_ip)
                dst_str = str(ipaddress.IPv4Address(dst_ip))
                proto = "TCP" if key.protocol == IPPROTO_TCP else "UDP"
                logger.info(f"  v4: {dst_str}:{key.dst_port} <- :{key.src_port} [{proto}] pid={pid} comm={get_comm(pid)}")
        if self._map_v6:
            for key, pid in self._map_v6.items():
                packed = b"".join(key.dst_ip[i].to_bytes(4, "big") for i in range(4))
                dst_str = str(ipaddress.IPv6Address(packed))
                proto = "TCP" if key.protocol == IPPROTO_TCP else "UDP"
                logger.info(f"  v6: [{dst_str}]:{key.dst_port} <- :{key.src_port} [{proto}] pid={pid} comm={get_comm(pid)}")
        logger.info("=== End Map Dump ===")

    def lookup_pid(self, dst_ip: str, src_port: int, dst_port: int, protocol: int = IPPROTO_TCP) -> int | None:
        """Look up PID for a connection tuple."""
        try:
            addr = ipaddress.ip_address(dst_ip)
        except ValueError:
            return None

        if isinstance(addr, ipaddress.IPv4Address):
            key = ConnKeyV4(
                dst_ip=socket.htonl(int(addr)),
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
            )
            return self._map_v4.get(key) if self._map_v4 else None
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
            return self._map_v6.get(key) if self._map_v6 else None

    def request(self, flow: http.HTTPFlow) -> None:
        # HTTP/HTTPS request (same handler for both)
        src_port = flow.client_conn.peername[1] if flow.client_conn.peername else 0
        dst_ip, dst_port = flow.server_conn.address if flow.server_conn.address else ("unknown", 0)
        url = flow.request.pretty_url

        pid = self.lookup_pid(dst_ip, src_port, dst_port)
        if pid:
            comm = get_comm(pid)
            logger.info(f"HTTP src_port={src_port} dst={dst_ip}:{dst_port} url={url} pid={pid} comm={comm}")
        else:
            logger.info(f"HTTP src_port={src_port} dst={dst_ip}:{dst_port} url={url} pid=?")

    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        # Non-HTTP TCP connection
        src_port = flow.client_conn.peername[1] if flow.client_conn.peername else 0
        dst_ip, dst_port = flow.server_conn.address if flow.server_conn.address else ("unknown", 0)

        pid = self.lookup_pid(dst_ip, src_port, dst_port)
        if pid:
            comm = get_comm(pid)
            logger.info(f"TCP src_port={src_port} dst={dst_ip}:{dst_port} pid={pid} comm={comm}")
        else:
            logger.info(f"TCP src_port={src_port} dst={dst_ip}:{dst_port} pid=?")

    def dns_request(self, flow: dns.DNSFlow) -> None:
        # DNS query - may be redirected from various sources
        src_port = flow.client_conn.peername[1] if flow.client_conn.peername else 0
        query_name = flow.request.questions[0].name if flow.request.questions else "?"

        # Get original destination (before iptables redirect)
        dst_ip, dst_port = flow.server_conn.address if flow.server_conn.address else (None, 53)

        pid = None
        # Try original destination first (if mitmproxy preserved it)
        if dst_ip:
            pid = self.lookup_pid(dst_ip, src_port, dst_port, protocol=IPPROTO_UDP)
        # Fall back to common loopback addresses (systemd-resolved, localhost)
        if not pid:
            pid = self.lookup_pid("127.0.0.53", src_port, 53, protocol=IPPROTO_UDP)
        if not pid:
            pid = self.lookup_pid("127.0.0.1", src_port, 53, protocol=IPPROTO_UDP)
        # Final fallback: DNS-specific map keyed by src_port only
        if not pid and self._map_dns:
            pid = self._map_dns.get(DnsKey(src_port=src_port))

        if pid:
            comm = get_comm(pid)
            logger.info(f"DNS src_port={src_port} name={query_name} pid={pid} comm={comm}")
        else:
            logger.info(f"DNS src_port={src_port} name={query_name} pid=?")


addons = [ConnectionLogger()]

if __name__ == "__main__":
    from mitmproxy.tools.main import mitmdump
    mitmdump(["-s", __file__, "--mode", "transparent", "--mode", "dns@8053", "--showhost", "--set", "block_global=false"])
