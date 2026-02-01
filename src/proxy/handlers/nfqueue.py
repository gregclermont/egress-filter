"""Netfilterqueue handler for UDP packets."""

from __future__ import annotations

# Optional imports - graceful degradation if not available
try:
    from netfilterqueue import NetfilterQueue

    HAS_NFQUEUE = True
except ImportError:
    HAS_NFQUEUE = False

try:
    from scapy.layers.dns import DNS
    from scapy.layers.inet import IP, UDP

    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

from .. import logging as proxy_logging
from ..bpf import BPFState
from ..policy import PolicyEnforcer, ProcessInfo
from ..proc import get_proc_info, is_proxy_process
from ..utils import IPPROTO_UDP


class NfqueueHandler:
    """Handle UDP via netfilterqueue (runs in mangle, before NAT).

    Flow:
        All UDP → nfqueue (mangle)
                      ↓
                haslayer(DNS)?
                 /        \\
               yes         no
                ↓           ↓
           mark=2        mark=4
           (redirect)    (fastpath)
           cache 4-tuple
                ↓           ↓
           repeat()     repeat()
                ↓           ↓
           mark=2 →     mark&4 → CONNMARK save
           RETURN       RETURN
                ↓           ↓
           nat: mark&2 → REDIRECT :8053
                ↓
           mitmproxy (dns_request looks up cache by src_port+txid)

    Fast-path (non-DNS only): The packet mark is saved to conntrack via CONNMARK.
    Subsequent packets with the same 4-tuple match connmark and skip nfqueue.
    DNS packets do NOT get fast-path - every query goes through nfqueue for logging.
    This prevents bypass where only the first DNS query would be proxied.

    We use repeat() instead of accept() because accept() skips remaining iptables
    rules, so the mark wouldn't be visible.
    """

    # Mark bits (can be combined)
    MARK_DNS_REDIRECT = 2  # Redirect to mitmproxy DNS port
    MARK_FASTPATH = 4  # Save to conntrack for fast-path
    MARK_DROP = 0  # Drop the packet (no marks)

    def __init__(self, bpf: BPFState, enforcer: PolicyEnforcer):
        """Initialize the handler.

        Args:
            bpf: BPF state for PID lookup
            enforcer: Policy enforcer (use audit_mode=True for observation only)
        """
        self.bpf = bpf
        self.enforcer = enforcer
        self.nfqueue = None
        self.queue_num = 1
        self.packet_count = 0  # For debugging fast-path
        self.dns_packet_count = 0  # For debugging BPF map after restart
        self.stale_packets_to_drain = 0  # Set on setup() from queue size
        self.stale_packets_drained = 0  # Telemetry: how many actually drained
        self.proxy_pid_detections = 0  # Telemetry: BPF returned proxy's own PID

    def handle_packet(self, pkt):
        """Process a packet from nfqueue. Enforces policy if enforcer is set."""
        self.packet_count += 1

        # Drain stale packets that were queued before we started.
        # After proxy restart, these are from clients that already timed out.
        if self.stale_packets_to_drain > 0:
            self.stale_packets_to_drain -= 1
            self.stale_packets_drained += 1
            pkt.drop()
            return

        mark = self.MARK_FASTPATH  # Default: just fast-path
        drop = False

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
                    pid = self.bpf.lookup_pid(
                        dst_ip, src_port, dst_port, protocol=IPPROTO_UDP
                    )

                    # If BPF returns proxy's own PID, this is likely ephemeral port
                    # reuse - treat as unknown PID rather than dropping the packet
                    if pid and is_proxy_process(pid):
                        self.proxy_pid_detections += 1
                        pid = None

                    proc_dict = get_proc_info(pid)

                    # DNS detection by packet structure (catches DNS on any port)
                    # This runs in mangle (before NAT), so we see the original destination
                    if ip.haslayer(DNS):
                        self.dns_packet_count += 1
                        dns_layer = ip[DNS]
                        txid = dns_layer.id

                        # Mark for redirect only (no fast-path for DNS - we want to see every query)
                        mark = self.MARK_DNS_REDIRECT
                        # Cache: (src_port, txid) -> (pid, dst_ip, dst_port)
                        # Logging happens in mitmproxy's dns_request() to avoid double-logging
                        cache_key = (src_port, txid)
                        self.bpf.dns_cache[cache_key] = (pid, dst_ip, dst_port)
                    else:
                        # Non-DNS UDP - check policy and log
                        decision = self.enforcer.check_udp(
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            proc=ProcessInfo.from_dict(proc_dict),
                        )

                        if decision.blocked:
                            drop = True

                        proxy_logging.log_connection(
                            type="udp",
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            policy=decision.policy,
                            **proc_dict,
                            src_port=src_port,
                            pid=pid,
                        )
        except Exception as e:
            proxy_logging.logger.warning(f"Error processing UDP packet: {e}")

        # Either drop or reinject the packet
        if drop:
            pkt.drop()
        else:
            # Set mark and use repeat() to reinject packet at start of chain.
            # This ensures iptables sees the mark (accept() may skip subsequent rules).
            # The CONNMARK save rule runs before NFQUEUE, so on repeat it saves
            # the mark to conntrack and returns, avoiding re-queuing.
            pkt.set_mark(mark)
            pkt.repeat()

    def _get_queue_size(self) -> int:
        """Read current queue size from /proc/net/netfilter/nfnetlink_queue.

        Format: queue_id port_id queue_total copy_mode copy_range ...
        Column 3 (0-indexed: 2) is queue_total - packets waiting in queue.
        """
        try:
            with open("/proc/net/netfilter/nfnetlink_queue") as f:
                for line in f:
                    fields = line.split()
                    if len(fields) >= 3 and int(fields[0]) == self.queue_num:
                        return int(fields[2])
        except (OSError, ValueError, IndexError):
            pass
        return 0

    def setup(self) -> bool:
        """Setup nfqueue binding. Returns True if successful."""
        if not HAS_NFQUEUE:
            proxy_logging.logger.warning(
                "netfilterqueue not available, skipping UDP handler"
            )
            return False

        # Check for stale packets before binding. These were queued before
        # we started (e.g., after proxy restart) - clients already timed out.
        self.stale_packets_to_drain = self._get_queue_size()
        if self.stale_packets_to_drain > 0:
            proxy_logging.logger.info(
                f"Will drain {self.stale_packets_to_drain} stale packets from queue"
            )

        self.nfqueue = NetfilterQueue()
        self.nfqueue.bind(self.queue_num, self.handle_packet)
        proxy_logging.logger.info(f"nfqueue bound to queue {self.queue_num}")
        return True

    def get_fd(self) -> int | None:
        """Get file descriptor for asyncio integration."""
        if self.nfqueue:
            return self.nfqueue.get_fd()
        return None

    def process_pending(self):
        """Process pending packets (call from asyncio)."""
        if self.nfqueue:
            # run(block=False) processes available packets without blocking
            before_count = self.packet_count
            self.nfqueue.run(block=False)
            processed = self.packet_count - before_count
            if processed > 0:
                proxy_logging.logger.debug(
                    f"[nfqueue] process_pending: processed {processed} packets"
                )

    def cleanup(self):
        """Cleanup nfqueue."""
        proxy_logging.logger.info(
            f"nfqueue stats: packets={self.packet_count} dns={self.dns_packet_count} "
            f"stale_drained={self.stale_packets_drained} proxy_pid_detections={self.proxy_pid_detections}"
        )
        if self.nfqueue:
            try:
                self.nfqueue.unbind()
            except Exception as e:
                proxy_logging.logger.warning(f"Error unbinding nfqueue: {e}")
