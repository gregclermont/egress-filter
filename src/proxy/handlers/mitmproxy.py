"""Mitmproxy addon for connection logging and policy enforcement."""

from __future__ import annotations

from mitmproxy import dns, http, tcp, tls

from .. import logging as proxy_logging
from ..bpf import BPFState
from ..policy import PolicyEnforcer, ProcessInfo
from ..proc import get_proc_info, is_container_process
from . import log_errors


class MitmproxyAddon:
    """Mitmproxy addon for PID tracking, connection logging, and policy enforcement."""

    def __init__(self, bpf: BPFState, enforcer: PolicyEnforcer):
        """Initialize the addon.

        Args:
            bpf: BPF state for PID lookup
            enforcer: Policy enforcer (use audit_mode=True for observation only)
        """
        self.bpf = bpf
        self.enforcer = enforcer

    @log_errors
    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        """Handle TLS ClientHello - passthrough for container processes.

        Container processes don't have access to mitmproxy's CA cert,
        so we skip MITM and just log the connection with SNI hostname.

        For non-container processes without SNI, we defer the policy decision
        to the request() hook where we'll have access to the Host header after
        TLS decryption.
        """
        src_port = (
            data.context.client.peername[1] if data.context.client.peername else 0
        )
        dst_ip, dst_port = (
            data.context.server.address
            if data.context.server.address
            else ("unknown", 0)
        )
        sni = data.client_hello.sni

        pid = self.bpf.lookup_pid(dst_ip, src_port, dst_port)
        proc_dict = get_proc_info(pid)
        is_container = pid and is_container_process(pid)

        # If we have SNI, enforce now
        # If no SNI but container (can't decrypt), enforce now with IP/DNS-cache
        # If no SNI and non-container (can decrypt), defer to request() hook
        # where we'll have access to the Host header
        should_enforce_now = sni or is_container

        if should_enforce_now:
            decision = self.enforcer.check_https(
                dst_ip=dst_ip,
                dst_port=dst_port,
                sni=sni,
                proc=ProcessInfo.from_dict(proc_dict),
            )

            if decision.blocked:
                proxy_logging.log_connection(
                    type="https",
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    host=sni,
                    policy=decision.policy,
                    **proc_dict,
                    src_port=src_port,
                    pid=pid,
                )
                # Kill the connection
                data.context.client.error = "Blocked by egress policy"
                return

            if is_container:
                # Log and skip MITM - pass through encrypted traffic unmodified
                proxy_logging.log_connection(
                    type="https",
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    host=sni,
                    policy=decision.policy,
                    **proc_dict,
                    src_port=src_port,
                    pid=pid,
                )
                data.ignore_connection = True
        # else: No SNI, can decrypt - defer to request() hook

    @log_errors
    def request(self, flow: http.HTTPFlow) -> None:
        """Handle HTTP/HTTPS request - log and optionally enforce policy.

        For HTTPS, this is called after TLS decryption (MITM). If the original
        TLS ClientHello had no SNI, this is where we enforce the policy using
        the Host header from the decrypted request.
        """
        src_port = flow.client_conn.peername[1] if flow.client_conn.peername else 0
        dst_ip, dst_port = (
            flow.server_conn.address if flow.server_conn.address else ("unknown", 0)
        )
        url = flow.request.pretty_url
        method = flow.request.method

        # Determine connection type from URL scheme
        conn_type = "https" if url.startswith("https://") else "http"

        pid = self.bpf.lookup_pid(dst_ip, src_port, dst_port)
        proc_dict = get_proc_info(pid)

        decision = self.enforcer.check_http(
            dst_ip=dst_ip,
            dst_port=dst_port,
            url=url,
            method=method,
            proc=ProcessInfo.from_dict(proc_dict),
        )

        if decision.blocked:
            proxy_logging.log_connection(
                type=conn_type,
                dst_ip=dst_ip,
                dst_port=dst_port,
                url=url,
                method=method,
                policy=decision.policy,
                **proc_dict,
                src_port=src_port,
                pid=pid,
            )
            # Return 403 Forbidden
            flow.response = http.Response.make(
                403,
                "Blocked by egress policy",
                {"Content-Type": "text/plain"},
            )
            return

        proxy_logging.log_connection(
            type=conn_type,
            dst_ip=dst_ip,
            dst_port=dst_port,
            url=url,
            method=method,
            policy=decision.policy,
            **proc_dict,
            src_port=src_port,
            pid=pid,
        )

    @log_errors
    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        """Handle raw TCP connection - log and optionally enforce policy."""
        src_port = flow.client_conn.peername[1] if flow.client_conn.peername else 0
        dst_ip, dst_port = (
            flow.server_conn.address if flow.server_conn.address else ("unknown", 0)
        )

        pid = self.bpf.lookup_pid(dst_ip, src_port, dst_port)
        proc_dict = get_proc_info(pid)

        decision = self.enforcer.check_tcp(
            dst_ip=dst_ip,
            dst_port=dst_port,
            proc=ProcessInfo.from_dict(proc_dict),
        )

        if decision.blocked:
            proxy_logging.log_connection(
                type="tcp",
                dst_ip=dst_ip,
                dst_port=dst_port,
                policy=decision.policy,
                **proc_dict,
                src_port=src_port,
                pid=pid,
            )
            flow.kill()
            return

        proxy_logging.log_connection(
            type="tcp",
            dst_ip=dst_ip,
            dst_port=dst_port,
            policy=decision.policy,
            **proc_dict,
            src_port=src_port,
            pid=pid,
        )

    @log_errors
    def dns_request(self, flow: dns.DNSFlow) -> None:
        """Handle DNS request - log and optionally enforce policy."""
        src_port = flow.client_conn.peername[1] if flow.client_conn.peername else 0
        query_name = flow.request.questions[0].name if flow.request.questions else None
        txid = flow.request.id

        # Get info from nfqueue cache (has original 4-tuple from before NAT)
        cache_key = (src_port, txid)
        cached = self.bpf.dns_cache.pop(cache_key, None)

        if cached:
            pid, dst_ip, dst_port = cached
            proc_dict = get_proc_info(pid)

            if query_name:
                decision = self.enforcer.check_dns(
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    query_name=query_name,
                    proc=ProcessInfo.from_dict(proc_dict),
                )

                if decision.blocked:
                    proxy_logging.log_connection(
                        type="dns",
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        name=query_name,
                        policy=decision.policy,
                        **proc_dict,
                        src_port=src_port,
                        pid=pid,
                    )
                    # Return REFUSED response
                    flow.response = dns.DNSMessage(
                        id=flow.request.id,
                        query=False,
                        op_code=flow.request.op_code,
                        authoritative_answer=False,
                        truncation=False,
                        recursion_desired=flow.request.recursion_desired,
                        recursion_available=False,
                        reserved=0,
                        response_code=5,  # REFUSED
                        questions=flow.request.questions,
                        answers=[],
                        authorities=[],
                        additionals=[],
                    )
                    return

                proxy_logging.log_connection(
                    type="dns",
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    name=query_name,
                    policy=decision.policy,
                    **proc_dict,
                    src_port=src_port,
                    pid=pid,
                )
        else:
            # Cache miss - nfqueue should have seen the packet first
            proxy_logging.logger.error(
                f"DNS cache miss: src_port={src_port} txid={txid} name={query_name}"
            )

    @log_errors
    def dns_response(self, flow: dns.DNSFlow) -> None:
        """Handle DNS response - record IPs for correlation."""
        if not flow.response:
            return

        query_name = flow.request.questions[0].name if flow.request.questions else None
        if not query_name:
            return

        # Extract IPs from A and AAAA records
        ips = []
        min_ttl = 300  # Default TTL if none found

        for answer in flow.response.answers:
            # Check for A record (type 1) or AAAA record (type 28)
            if hasattr(answer, "data"):
                if answer.type == 1:  # A record
                    ips.append(str(answer.data))
                    if hasattr(answer, "ttl"):
                        min_ttl = min(min_ttl, answer.ttl)
                # Note: AAAA records are blocked at kernel level, but handle anyway
                elif answer.type == 28:  # AAAA record
                    ips.append(str(answer.data))
                    if hasattr(answer, "ttl"):
                        min_ttl = min(min_ttl, answer.ttl)

        if ips:
            self.enforcer.record_dns_response(query_name, ips, min_ttl)
            proxy_logging.logger.debug(
                f"DNS cache: {query_name} -> {ips} (ttl={min_ttl})"
            )
