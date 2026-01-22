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
import atexit
import ctypes
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone
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
CONNECTIONS_FILE = os.environ.get("CONNECTIONS_FILE", "/tmp/connections.jsonl")
MITMPROXY_LOG_FILE = os.environ.get("MITMPROXY_LOG_FILE", "/tmp/mitmproxy.log")
VERBOSE = os.environ.get("VERBOSE", "0") == "1"

# Operational logger (human-readable)
logger = logging.getLogger("egress_proxy")
logger.setLevel(logging.INFO)
logger.propagate = False
logger.handlers.clear()
_handler = logging.FileHandler(LOG_FILE)
_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
logger.addHandler(_handler)

# Connection events logger (JSONL format)
_conn_file = open(CONNECTIONS_FILE, "a", buffering=1)  # Line-buffered


def log_connection(**kwargs) -> None:
    """Log a connection event as JSONL (pid and src_port at end for readability)."""
    # Extract fields we want at the end
    pid = kwargs.pop("pid", None)
    src_port = kwargs.pop("src_port", None)
    # Build event with ts first, then remaining fields, then pid/src_port at end
    event = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds")}
    event.update(kwargs)
    if src_port is not None:
        event["src_port"] = src_port
    if pid is not None:
        event["pid"] = pid
    _conn_file.write(json.dumps(event, separators=(",", ":")) + "\n")


# Configure mitmproxy's internal logging (only in verbose mode)
if VERBOSE:
    _mitmproxy_handler = logging.FileHandler(MITMPROXY_LOG_FILE)
    _mitmproxy_handler.setFormatter(logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s'))
    for mlog_name in ["mitmproxy", "mitmproxy.proxy", "mitmproxy.options"]:
        mlog = logging.getLogger(mlog_name)
        mlog.setLevel(logging.DEBUG)
        mlog.addHandler(_mitmproxy_handler)


def get_proc_info(pid: int | None) -> dict:
    """Get process info from /proc: exe, cmdline."""
    if not pid:
        return {}
    result = {}
    try:
        result["exe"] = os.readlink(f"/proc/{pid}/exe")
    except (OSError, FileNotFoundError):
        pass
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        if cmdline:
            # Null-separated args -> list
            result["cmdline"] = [arg.decode("utf-8", errors="replace") for arg in cmdline.rstrip(b"\x00").split(b"\x00")]
    except (OSError, FileNotFoundError):
        pass
    return result


def get_cgroup() -> str:
    """Get the cgroup path for the current process."""
    cgroup_info = Path("/proc/self/cgroup").read_text().strip()
    cgroup_rel = cgroup_info.split(":")[-1]
    return f"/sys/fs/cgroup{cgroup_rel}"


def ip_to_int(ip_str: str) -> int:
    """Convert IP string to integer matching BPF map key format.

    BPF stores sin_addr.s_addr (network byte order) directly into a u32.
    On little-endian machines (x86), this means the bytes are stored as-is
    but interpreted as little-endian. We must match that interpretation.

    Handles IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) by extracting the IPv4 part.
    """
    import socket
    import struct
    # Handle IPv4-mapped IPv6 addresses
    if ip_str.startswith("::ffff:"):
        ip_str = ip_str[7:]  # Extract the IPv4 portion
    # Use little-endian to match how BPF interprets the network-order bytes
    return struct.unpack("<I", socket.inet_aton(ip_str))[0]


class SharedState:
    """Shared state between mitmproxy addon and nfqueue handler."""

    def __init__(self, bpf_path: str | None = None):
        # Default BPF path relative to this script (src/proxy/ -> dist/bpf/)
        if bpf_path is None:
            repo_root = Path(__file__).parent.parent.parent.resolve()
            bpf_path = str(repo_root / "dist" / "bpf" / "conn_tracker.bpf.o")
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
    """Mitmproxy addon for PID tracking and connection logging."""

    def request(self, flow: http.HTTPFlow) -> None:
        src_port = flow.client_conn.peername[1] if flow.client_conn.peername else 0
        dst_ip, dst_port = flow.server_conn.address if flow.server_conn.address else ("unknown", 0)
        url = flow.request.pretty_url

        pid = shared_state.lookup_pid(dst_ip, src_port, dst_port)
        log_connection(
            type="http",
            dst_ip=dst_ip,
            dst_port=dst_port,
            url=url,
            **get_proc_info(pid),
            src_port=src_port,
            pid=pid,
        )

    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        src_port = flow.client_conn.peername[1] if flow.client_conn.peername else 0
        dst_ip, dst_port = flow.server_conn.address if flow.server_conn.address else ("unknown", 0)

        pid = shared_state.lookup_pid(dst_ip, src_port, dst_port)
        log_connection(
            type="tcp",
            dst_ip=dst_ip,
            dst_port=dst_port,
            **get_proc_info(pid),
            src_port=src_port,
            pid=pid,
        )

    def dns_request(self, flow: dns.DNSFlow) -> None:
        src_port = flow.client_conn.peername[1] if flow.client_conn.peername else 0
        query_name = flow.request.questions[0].name if flow.request.questions else None
        txid = flow.request.id

        # Get info from nfqueue cache (has original 4-tuple from before NAT)
        cache_key = (src_port, txid)
        cached = shared_state.dns_cache.pop(cache_key, None)

        if cached:
            pid, dst_ip, dst_port = cached
            log_connection(
                type="dns",
                dst_ip=dst_ip,
                dst_port=dst_port,
                name=query_name,
                **get_proc_info(pid),
                src_port=src_port,
                pid=pid,
            )
        else:
            # Cache miss - nfqueue should have seen the packet first
            logger.error(f"DNS cache miss: src_port={src_port} txid={txid} name={query_name}")


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

                    # DNS detection by packet structure (catches DNS on any port)
                    # This runs in mangle (before NAT), so we see the original destination
                    if ip.haslayer(DNS):
                        dns_layer = ip[DNS]
                        txid = dns_layer.id
                        # Mark packet for iptables to redirect to mitmproxy
                        pkt.set_mark(2)
                        # Cache: (src_port, txid) -> (pid, dst_ip, dst_port)
                        # Logging happens in mitmproxy's dns_request() to avoid double-logging
                        cache_key = (src_port, txid)
                        shared_state.dns_cache[cache_key] = (pid, dst_ip, dst_port)
                    else:
                        # Non-DNS UDP - log here (not handled by mitmproxy)
                        log_connection(
                            type="udp",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            **get_proc_info(pid),
                            src_port=src_port,
                            pid=pid,
                        )
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
    master = None
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
        raise  # Must re-raise for proper task cancellation
    except Exception as e:
        logger.error(f"mitmproxy failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise
    finally:
        if master:
            logger.info("Shutting down mitmproxy master...")
            master.shutdown()


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


# Graceful shutdown timeout (seconds)
SHUTDOWN_TIMEOUT = 3.0


def log_all_tasks(prefix: str = ""):
    """Log status of all asyncio tasks."""
    tasks = asyncio.all_tasks()
    logger.info(f"{prefix}Active asyncio tasks: {len(tasks)}")
    for task in tasks:
        logger.info(f"  Task '{task.get_name()}': done={task.done()}, cancelled={task.cancelled()}")


# Track if cleanup has run to avoid double cleanup
_cleanup_done = False


def cleanup_on_exit():
    """Cleanup BPF resources on exit (atexit handler)."""
    global _cleanup_done
    if _cleanup_done:
        return
    _cleanup_done = True
    logger.info("atexit: cleaning up BPF...")
    shared_state.cleanup_bpf()
    _conn_file.close()


# Register atexit handler early
atexit.register(cleanup_on_exit)


async def shutdown_tasks(tasks: list, timeout: float = SHUTDOWN_TIMEOUT):
    """Cancel tasks and wait for them to finish with timeout."""
    # Cancel all tasks
    for task in tasks:
        if not task.done():
            logger.info(f"Cancelling task: {task.get_name()}")
            task.cancel()

    if not tasks:
        return

    # Wait for tasks to finish with timeout
    try:
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=timeout
        )
        for task, result in zip(tasks, results):
            if isinstance(result, asyncio.CancelledError):
                logger.info(f"Task {task.get_name()} cancelled")
            elif isinstance(result, Exception):
                logger.warning(f"Task {task.get_name()} ended with error: {result}")
            else:
                logger.info(f"Task {task.get_name()} ended cleanly")
    except asyncio.TimeoutError:
        logger.warning(f"Shutdown timed out after {timeout}s, some tasks may not have cleaned up")
        log_all_tasks("After timeout: ")


async def main():
    """Main entry point."""
    global _cleanup_done

    logger.info("=" * 50)
    logger.info("Unified Proxy Starting")
    logger.info(f"PID: {os.getpid()}")
    logger.info("=" * 50)

    # Setup BPF
    shared_state.setup_bpf()

    # Setup signal handlers
    loop = asyncio.get_event_loop()
    stop_event = asyncio.Event()

    def signal_handler(signum):
        sig_name = signal.Signals(signum).name
        logger.info(f"Received signal {sig_name} ({signum})")
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        loop.add_signal_handler(sig, lambda s=sig: signal_handler(s))

    # Create tasks
    nfqueue_handler = NfqueueHandler()
    mitmproxy_task = asyncio.create_task(run_mitmproxy(), name="mitmproxy")
    nfqueue_task = asyncio.create_task(run_nfqueue(nfqueue_handler), name="nfqueue")
    tasks = [mitmproxy_task, nfqueue_task]

    try:
        # Wait for stop signal OR task failure
        stop_task = asyncio.create_task(stop_event.wait(), name="stop_signal")
        done, _ = await asyncio.wait(
            [stop_task, mitmproxy_task, nfqueue_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        # Check what triggered the exit
        for task in done:
            if task != stop_task and task.exception():
                logger.error(f"Task {task.get_name()} failed: {task.exception()}")

    finally:
        # Always cleanup, even on exception
        logger.info("Shutting down...")
        stop_task.cancel()  # Cancel the stop_event.wait() task
        await shutdown_tasks(tasks)

        # Cleanup BPF (also handled by atexit as fallback)
        _cleanup_done = True
        shared_state.cleanup_bpf()
        logger.info("Shutdown complete")
        logger.info("=" * 50)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
