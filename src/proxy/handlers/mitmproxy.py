"""Mitmproxy addon for connection logging."""

from mitmproxy import http, tcp, dns, tls

from ..bpf import BPFState
from .. import logging as proxy_logging
from ..proc import get_proc_info, is_container_process


class MitmproxyAddon:
    """Mitmproxy addon for PID tracking and connection logging."""

    def __init__(self, bpf: BPFState):
        self.bpf = bpf

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        """Handle TLS ClientHello - passthrough for container processes.

        Container processes don't have access to mitmproxy's CA cert,
        so we skip MITM and just log the connection with SNI hostname.
        """
        src_port = data.context.client.peername[1] if data.context.client.peername else 0
        dst_ip, dst_port = data.context.server.address if data.context.server.address else ("unknown", 0)
        sni = data.client_hello.sni

        pid = self.bpf.lookup_pid(dst_ip, src_port, dst_port)

        if pid and is_container_process(pid):
            # Log the connection with SNI as the hostname
            proxy_logging.log_connection(
                type="https",
                dst_ip=dst_ip,
                dst_port=dst_port,
                host=sni,
                **get_proc_info(pid),
                src_port=src_port,
                pid=pid,
            )
            # Skip MITM - pass through encrypted traffic unmodified
            data.ignore_connection = True

    def request(self, flow: http.HTTPFlow) -> None:
        src_port = flow.client_conn.peername[1] if flow.client_conn.peername else 0
        dst_ip, dst_port = flow.server_conn.address if flow.server_conn.address else ("unknown", 0)
        url = flow.request.pretty_url

        pid = self.bpf.lookup_pid(dst_ip, src_port, dst_port)
        proxy_logging.log_connection(
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

        pid = self.bpf.lookup_pid(dst_ip, src_port, dst_port)
        proxy_logging.log_connection(
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
        cached = self.bpf.dns_cache.pop(cache_key, None)

        if cached:
            pid, dst_ip, dst_port = cached
            proxy_logging.log_connection(
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
            proxy_logging.logger.error(f"DNS cache miss: src_port={src_port} txid={txid} name={query_name}")
