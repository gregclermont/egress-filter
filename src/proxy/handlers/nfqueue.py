"""Netfilterqueue handler for UDP packets."""

# Optional imports - graceful degradation if not available
try:
    from netfilterqueue import NetfilterQueue
    HAS_NFQUEUE = True
except ImportError:
    HAS_NFQUEUE = False

try:
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

from ..bpf import BPFState
from .. import logging as proxy_logging
from ..proc import get_proc_info
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
    MARK_DNS_REDIRECT = 2   # Redirect to mitmproxy DNS port
    MARK_FASTPATH = 4       # Save to conntrack for fast-path

    def __init__(self, bpf: BPFState):
        self.bpf = bpf
        self.nfqueue = None
        self.queue_num = 1
        self.packet_count = 0  # For debugging fast-path

    def handle_packet(self, pkt):
        """Process a packet from nfqueue. ALWAYS accepts for safety."""
        self.packet_count += 1
        mark = self.MARK_FASTPATH  # Default: just fast-path

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
                    pid = self.bpf.lookup_pid(dst_ip, src_port, dst_port, protocol=IPPROTO_UDP)

                    # DNS detection by packet structure (catches DNS on any port)
                    # This runs in mangle (before NAT), so we see the original destination
                    if ip.haslayer(DNS):
                        dns_layer = ip[DNS]
                        txid = dns_layer.id
                        # Mark for redirect only (no fast-path for DNS - we want to see every query)
                        mark = self.MARK_DNS_REDIRECT
                        # Cache: (src_port, txid) -> (pid, dst_ip, dst_port)
                        # Logging happens in mitmproxy's dns_request() to avoid double-logging
                        cache_key = (src_port, txid)
                        self.bpf.dns_cache[cache_key] = (pid, dst_ip, dst_port)
                    else:
                        # Non-DNS UDP - log here (not handled by mitmproxy)
                        proxy_logging.log_connection(
                            type="udp",
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            **get_proc_info(pid),
                            src_port=src_port,
                            pid=pid,
                        )
        except Exception as e:
            proxy_logging.logger.warning(f"Error processing UDP packet: {e}")

        # Set mark and use repeat() to reinject packet at start of chain.
        # This ensures iptables sees the mark (accept() may skip subsequent rules).
        # The CONNMARK save rule runs before NFQUEUE, so on repeat it saves
        # the mark to conntrack and returns, avoiding re-queuing.
        pkt.set_mark(mark)
        pkt.repeat()

    def setup(self) -> bool:
        """Setup nfqueue binding. Returns True if successful."""
        if not HAS_NFQUEUE:
            proxy_logging.logger.warning("netfilterqueue not available, skipping UDP handler")
            return False

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
            self.nfqueue.run(block=False)

    def cleanup(self):
        """Cleanup nfqueue."""
        proxy_logging.logger.info(f"nfqueue processed {self.packet_count} packets")
        if self.nfqueue:
            try:
                self.nfqueue.unbind()
            except Exception as e:
                proxy_logging.logger.warning(f"Error unbinding nfqueue: {e}")
