#!/usr/bin/env python3
"""
Unified egress proxy with mitmproxy (TCP/DNS) and netfilterqueue (UDP).

Handles:
- TCP/HTTP/HTTPS: mitmproxy transparent mode
- DNS (UDP:53): mitmproxy DNS mode
- Other UDP: netfilterqueue logging (accept all for now)

All traffic is attributed to PIDs via BPF maps.
"""

import asyncio
import ctypes
import logging
import os
import signal
import sys
from pathlib import Path

# Optional imports - graceful degradation if not available
try:
    from netfilterqueue import NetfilterQueue
    HAS_NFQUEUE = True
except ImportError:
    HAS_NFQUEUE = False
    print("Warning: netfilterqueue not available, UDP logging disabled")

try:
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

import tinybpf
from mitmproxy import http, tcp, dns, ctx
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

# Constants
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# BPF map key structures
class ConnKeyV4(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
    ]


# Logging setup
LOG_FILE = os.environ.get("PROXY_LOG_FILE", "/tmp/proxy.log")
logger = logging.getLogger("unified_proxy")
logger.setLevel(logging.INFO)
logger.propagate = False
logger.handlers.clear()
_handler = logging.FileHandler(LOG_FILE)
_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
logger.addHandler(_handler)
# Also log to stderr for debugging
_stderr = logging.StreamHandler()
_stderr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
logger.addHandler(_stderr)


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


def ip_to_int(ip_str: str) -> int:
    """Convert IP string to integer (network byte order).

    Handles IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) by extracting the IPv4 part.
    """
    import socket
    import struct
    # Handle IPv4-mapped IPv6 addresses
    if ip_str.startswith("::ffff:"):
        ip_str = ip_str[7:]  # Extract the IPv4 portion
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]


class SharedState:
    """Shared state between mitmproxy addon and nfqueue handler."""

    def __init__(self, bpf_path: str = "src/bpf/port_tracker.bpf.o"):
        self.bpf_obj = None
        self.bpf_links = []
        self.map_v4 = None
        self.running = False
        self.bpf_path = bpf_path
        # DNS 4-tuple cache: (src_port, txid) -> (pid, dst_ip, dst_port)
        # Populated by nfqueue (before NAT), consumed by mitmproxy (after NAT)
        self.dns_cache = {}

    def setup_bpf(self):
        """Load and attach BPF programs."""
        cgroup = get_cgroup()
        logger.info(f"Attaching to cgroup {cgroup}")

        logger.info(f"Loading BPF from {self.bpf_path}")
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

        self.running = True
        logger.info("BPF loaded and attached")

    def cleanup_bpf(self):
        """Cleanup BPF resources."""
        logger.info("Cleaning up BPF...")
        for link in self.bpf_links:
            try:
                link.destroy()
            except Exception as e:
                logger.warning(f"Error destroying BPF link: {e}")
        self.bpf_links.clear()
        if self.bpf_obj:
            self.bpf_obj.__exit__(None, None, None)
        self.running = False

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


# Global shared state
shared_state = SharedState()


class MitmproxyAddon:
    """Mitmproxy addon for PID tracking."""

    def request(self, flow: http.HTTPFlow) -> None:
        src_port = flow.client_conn.peername[1] if flow.client_conn.peername else 0
        dst_ip, dst_port = flow.server_conn.address if flow.server_conn.address else ("unknown", 0)
        url = flow.request.pretty_url

        pid = shared_state.lookup_pid(dst_ip, src_port, dst_port)
        comm = get_comm(pid) if pid else "?"
        logger.info(f"HTTP src_port={src_port} dst={dst_ip}:{dst_port} url={url} pid={pid or '?'} comm={comm}")

    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        src_port = flow.client_conn.peername[1] if flow.client_conn.peername else 0
        dst_ip, dst_port = flow.server_conn.address if flow.server_conn.address else ("unknown", 0)

        pid = shared_state.lookup_pid(dst_ip, src_port, dst_port)
        comm = get_comm(pid) if pid else "?"
        logger.info(f"TCP src_port={src_port} dst={dst_ip}:{dst_port} pid={pid or '?'} comm={comm}")

    def dns_request(self, flow: dns.DNSFlow) -> None:
        src_port = flow.client_conn.peername[1] if flow.client_conn.peername else 0
        query_name = flow.request.questions[0].name if flow.request.questions else "?"
        txid = flow.request.id

        # Get info from nfqueue cache (has original 4-tuple from before NAT)
        cache_key = (src_port, txid)
        cached = shared_state.dns_cache.pop(cache_key, None)

        if cached:
            pid, original_dst_ip, original_dst_port = cached
            comm = get_comm(pid) if pid else "?"
            logger.info(f"DNS src_port={src_port} dst={original_dst_ip}:{original_dst_port} name={query_name} txid={txid} pid={pid or '?'} comm={comm}")
        else:
            # Cache miss - this is a bug, nfqueue should have seen the packet first
            logger.error(f"DNS cache miss! src_port={src_port} txid={txid} name={query_name} - nfqueue didn't see this packet")


class NfqueueHandler:
    """Handle UDP via netfilterqueue (runs in mangle, before NAT).

    Flow:
        All UDP → nfqueue (mangle)
                      ↓
                haslayer(DNS)?
                 /        \\
               yes         no
                ↓           ↓
           mark=2        (just log)
           cache 4-tuple
                ↓
           nat: mark=2 → REDIRECT :8053
                ↓
           mitmproxy (dns_request looks up cache by src_port+txid)
    """

    def __init__(self):
        self.nfqueue = None
        self.queue_num = 1

    def handle_packet(self, pkt):
        """Process a packet from nfqueue. ALWAYS accepts for safety."""
        try:
            if HAS_SCAPY:
                raw = pkt.get_payload()
                ip = IP(raw)

                if ip.haslayer(UDP):
                    udp = ip[UDP]
                    src_ip = ip.src
                    dst_ip = ip.dst
                    src_port = udp.sport
                    dst_port = udp.dport

                    # Look up PID
                    pid = shared_state.lookup_pid(dst_ip, src_port, dst_port, protocol=IPPROTO_UDP)
                    comm = get_comm(pid) if pid else "?"

                    # DNS detection by packet structure (catches DNS on any port)
                    # This runs in mangle (before NAT), so we see the original destination
                    if ip.haslayer(DNS):
                        dns_layer = ip[DNS]
                        txid = dns_layer.id
                        # Mark packet for iptables to redirect to mitmproxy
                        pkt.set_mark(2)
                        # Cache: (src_port, txid) -> (pid, dst_ip, dst_port)
                        cache_key = (src_port, txid)
                        shared_state.dns_cache[cache_key] = (pid, dst_ip, dst_port)
                        logger.info(f"DNS(nfq) src={src_ip}:{src_port} dst={dst_ip}:{dst_port} txid={txid} pid={pid or '?'} comm={comm} mark=2")
                    else:
                        # Non-DNS UDP
                        logger.info(f"UDP src={src_ip}:{src_port} dst={dst_ip}:{dst_port} pid={pid or '?'} comm={comm}")
        except Exception as e:
            logger.warning(f"Error processing UDP packet: {e}")

        # ALWAYS accept - we're just logging for now
        pkt.accept()

    def setup(self):
        """Setup nfqueue binding."""
        if not HAS_NFQUEUE:
            logger.warning("netfilterqueue not available, skipping UDP handler")
            return False

        self.nfqueue = NetfilterQueue()
        self.nfqueue.bind(self.queue_num, self.handle_packet)
        logger.info(f"nfqueue bound to queue {self.queue_num}")
        return True

    def get_fd(self):
        """Get file descriptor for asyncio integration."""
        if self.nfqueue:
            return self.nfqueue.get_fd()
        return None

    def process_pending(self):
        """Process pending packets (call from asyncio)."""
        if self.nfqueue:
            # run(block=False) processes available packets without blocking
            self.nfqueue.run(block=False)

    def cleanup(self):
        """Cleanup nfqueue."""
        if self.nfqueue:
            try:
                self.nfqueue.unbind()
            except Exception as e:
                logger.warning(f"Error unbinding nfqueue: {e}")


async def run_mitmproxy():
    """Run mitmproxy with our addon."""
    logger.info("Initializing mitmproxy...")
    try:
        opts = Options(
            mode=["transparent", "dns@8053"],
            showhost=True,
        )
        master = DumpMaster(opts)
        master.addons.add(MitmproxyAddon())
        logger.info("Starting mitmproxy on port 8080 (TCP) and 8053 (DNS)...")
        await master.run()
    except asyncio.CancelledError:
        logger.info("mitmproxy cancelled")
        master.shutdown()
    except Exception as e:
        logger.error(f"mitmproxy failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise


async def run_nfqueue(handler: NfqueueHandler):
    """Run nfqueue handler integrated with asyncio."""
    if not handler.setup():
        return

    fd = handler.get_fd()
    if fd is None:
        return

    loop = asyncio.get_event_loop()
    loop.add_reader(fd, handler.process_pending)

    logger.info("nfqueue handler running")
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        logger.info("nfqueue cancelled")
    finally:
        loop.remove_reader(fd)
        handler.cleanup()


async def main():
    """Main entry point."""
    logger.info("=" * 50)
    logger.info("Unified Proxy Starting")
    logger.info("=" * 50)

    # Setup BPF
    shared_state.setup_bpf()

    # Setup signal handlers
    loop = asyncio.get_event_loop()
    stop_event = asyncio.Event()

    def signal_handler():
        logger.info("Received shutdown signal")
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    # Create tasks
    nfqueue_handler = NfqueueHandler()
    mitmproxy_task = asyncio.create_task(run_mitmproxy(), name="mitmproxy")
    nfqueue_task = asyncio.create_task(run_nfqueue(nfqueue_handler), name="nfqueue")
    tasks = [mitmproxy_task, nfqueue_task]

    # Wait for stop signal OR task failure
    stop_task = asyncio.create_task(stop_event.wait(), name="stop_signal")
    done, pending = await asyncio.wait(
        [stop_task, mitmproxy_task, nfqueue_task],
        return_when=asyncio.FIRST_COMPLETED,
    )

    # Check if a task failed
    for task in done:
        if task != stop_task and task.exception():
            logger.error(f"Task {task.get_name()} failed: {task.exception()}")

    # Cancel remaining tasks
    logger.info("Shutting down...")
    for task in pending:
        task.cancel()
    for task in tasks:
        if not task.done():
            task.cancel()

    await asyncio.gather(*tasks, return_exceptions=True)

    # Cleanup
    shared_state.cleanup_bpf()
    logger.info("Shutdown complete")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
