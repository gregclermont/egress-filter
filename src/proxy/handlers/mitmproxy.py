"""Mitmproxy addon for connection logging and policy enforcement."""

from __future__ import annotations

from mitmproxy import dns, http, tcp, tls

from .. import logging as proxy_logging
from ..bpf import BPFState
from ..policy import PolicyEnforcer, ProcessInfo
from ..purl import parse_registry_url
from ..proc import get_proc_info
from . import log_errors


class MitmproxyAddon:
    """Mitmproxy addon for PID tracking, connection logging, and policy enforcement."""

    def __init__(self, bpf: BPFState, enforcer: PolicyEnforcer, socket_dev=None,
                 github_token=None, oidc_token_url=None, oidc_token=None):
        """Initialize the addon.

        Args:
            bpf: BPF state for PID lookup
            enforcer: Policy enforcer (use audit_mode=True for observation only)
            socket_dev: Optional SocketDevClient for package security checks
            github_token: Optional GITHUB_TOKEN for tagging API requests in logs
            oidc_token_url: Optional ACTIONS_ID_TOKEN_REQUEST_URL for OIDC detection
            oidc_token: Optional ACTIONS_ID_TOKEN_REQUEST_TOKEN for OIDC detection
        """
        self.bpf = bpf
        self.enforcer = enforcer
        self.socket_dev = socket_dev
        self._github_token = github_token
        self._oidc_token_url = oidc_token_url
        self._oidc_token = oidc_token
        # Stash allowed DNS request context for dns_response to log with answers.
        # Keyed by flow.id (a UUID string assigned at flow creation).
        self._pending_dns: dict[str, dict] = {}
        # Track connections where upstream TLS cert validation should be skipped.
        # Keyed by (src_port, dst_ip, dst_port) tuple, set in tls_clienthello,
        # consumed by tls_start_server and request.
        self._insecure_conns: dict[tuple, bool] = {}

    def _is_github_token(self, flow: http.HTTPFlow) -> bool:
        """Check if this request uses the workflow's GITHUB_TOKEN or OIDC token."""
        if not self._github_token and not self._oidc_token_url:
            return False
        auth = flow.request.headers.get("authorization", "")
        if not auth:
            return False
        # Auth scheme is case-insensitive per RFC 7235; token value is case-sensitive
        parts = auth.split(None, 1)
        if len(parts) != 2:
            return False
        scheme, credential = parts
        scheme_lower = scheme.lower()
        # Check GITHUB_TOKEN on api.github.com and uploads.github.com
        # Use pretty_host: in transparent mode, flow.request.host returns the IP address
        if self._github_token:
            host = flow.request.pretty_host
            if host in ("api.github.com", "uploads.github.com"):
                if scheme_lower in ("token", "bearer") and credential == self._github_token:
                    return True
        # Check OIDC token request
        if self._oidc_token_url and self._oidc_token:
            url = flow.request.pretty_url
            if (url.startswith(self._oidc_token_url)
                    and scheme_lower == "bearer"
                    and credential == self._oidc_token):
                return True
        return False

    @log_errors
    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        """Handle TLS ClientHello - enforce policy or defer to request().

        If we have SNI, enforce the policy now at the hostname level.
        The connection is allowed through to MITM so that request() can
        evaluate the full URL with path and method.

        If no SNI, defer the policy decision to request() where we'll
        have access to the Host header after TLS decryption.
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

        if sni:
            pid = self.bpf.lookup_pid(dst_ip, src_port, dst_port)
            proc_dict = get_proc_info(pid)

            decision = self.enforcer.check_https(
                dst_ip=dst_ip,
                dst_port=dst_port,
                sni=sni,
                proc=ProcessInfo.from_dict(proc_dict),
                can_mitm=True,
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
            elif decision.passthrough:
                proxy_logging.log_connection(
                    type="https",
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    host=sni,
                    policy=decision.policy,
                    passthrough=True,
                    **proc_dict,
                    src_port=src_port,
                    pid=pid,
                )
                data.ignore_connection = True
            elif decision.insecure:
                # Track for tls_start_server to skip upstream cert validation.
                # Don't log here — request() will log with full URL.
                self._insecure_conns[(src_port, dst_ip, dst_port)] = True
        else:
            # No SNI — still check if dst_ip matches an insecure rule so
            # tls_start_server can skip upstream cert validation.  The full
            # policy decision is deferred to request() after MITM.
            pid = self.bpf.lookup_pid(dst_ip, src_port, dst_port)
            proc_dict = get_proc_info(pid)
            decision = self.enforcer.check_https(
                dst_ip=dst_ip,
                dst_port=dst_port,
                sni=None,
                proc=ProcessInfo.from_dict(proc_dict),
                can_mitm=True,
            )
            if decision.insecure:
                self._insecure_conns[(src_port, dst_ip, dst_port)] = True

    @log_errors
    def tls_start_server(self, tls_start: tls.TlsData) -> None:
        """Handle TLS connection to upstream server — skip cert validation if insecure.

        When a connection was marked insecure in tls_clienthello, we set
        SSL.VERIFY_NONE on the upstream TLS context so mitmproxy doesn't
        reject self-signed or untrusted upstream certificates.
        """
        src_port = (
            tls_start.context.client.peername[1]
            if tls_start.context.client.peername
            else 0
        )
        dst_ip, dst_port = (
            tls_start.context.server.address
            if tls_start.context.server.address
            else ("unknown", 0)
        )

        conn_key = (src_port, dst_ip, dst_port)
        if conn_key in self._insecure_conns and tls_start.ssl_conn:
            from OpenSSL import SSL

            # Modify context to skip certificate verification
            ctx = tls_start.ssl_conn.get_context()
            ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)

            # Re-create the SSL connection so that VERIFY_NONE is applied.
            # OpenSSL copies verify_mode from context at SSL_new() time;
            # modifying the context afterwards has no effect on existing
            # SSL objects.
            sni = tls_start.context.client.sni
            new_conn = SSL.Connection(ctx)
            if sni:
                new_conn.set_tlsext_host_name(sni.encode("ascii"))
            new_conn.set_connect_state()
            tls_start.ssl_conn = new_conn

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

        # Check if this connection was marked insecure at TLS time
        insecure_kwargs = {}
        conn_key = (src_port, dst_ip, dst_port)
        if self._insecure_conns.pop(conn_key, False):
            insecure_kwargs["insecure"] = True

        # Detect if this request uses the workflow's GITHUB_TOKEN or OIDC token
        token_kwargs = {}
        if self._is_github_token(flow):
            token_kwargs["github_token"] = True

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
                **insecure_kwargs,
                **token_kwargs,
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

        # Socket.dev package security check (after policy allows, before logging)
        if self.socket_dev:
            pkg = parse_registry_url(url)
            if pkg:
                result = self.socket_dev.check(pkg.purl)
                if result and result.blocked:
                    proxy_logging.log_connection(
                        type=conn_type,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        url=url,
                        method=method,
                        policy="deny",
                        security_block=True,
                        purl=pkg.purl,
                        reasons=result.reasons,
                        **insecure_kwargs,
                        **token_kwargs,
                        **proc_dict,
                        src_port=src_port,
                        pid=pid,
                    )
                    flow.response = http.Response.make(
                        403,
                        f"Blocked by Socket.dev: {pkg.purl}",
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
            **insecure_kwargs,
            **token_kwargs,
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

                # Stash context for dns_response to log with resolved IPs
                self._pending_dns[flow.id] = dict(
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
        """Handle DNS response - record IPs for correlation and log resolved addresses."""
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
            if answer.type == 1:  # A record
                ips.append(str(answer.ipv4_address))
                if hasattr(answer, "ttl"):
                    min_ttl = min(min_ttl, answer.ttl)
            # Note: AAAA records are blocked at kernel level, but handle anyway
            elif answer.type == 28:  # AAAA record
                ips.append(str(answer.ipv6_address))
                if hasattr(answer, "ttl"):
                    min_ttl = min(min_ttl, answer.ttl)

        if ips:
            self.enforcer.record_dns_response(query_name, ips, min_ttl)
            proxy_logging.logger.debug(
                f"DNS cache: {query_name} -> {ips} (ttl={min_ttl})"
            )

        # Log dns_response event with full context from the request + resolved IPs
        conn_dict = self._pending_dns.pop(flow.id, None)
        if conn_dict:
            proxy_logging.log_connection(
                type="dns_response",
                answers=ips,
                ttl=min_ttl,
                **conn_dict,
            )

    @log_errors
    def tls_failed_client(self, data: tls.TlsData) -> None:
        """Handle TLS handshake failure with client.

        This fires when a client rejects our CA cert. Common causes:
        - Container process whose runtime doesn't use the system CA store
          or the injected env vars (e.g., Java without keytool import)
        - Host process with a custom/embedded trust store
        - Certificate pinning
        """
        src_port = data.context.client.peername[1] if data.context.client.peername else 0
        dst_ip, dst_port = (
            data.context.server.address
            if data.context.server.address
            else ("unknown", 0)
        )
        sni = data.context.client.sni

        pid = self.bpf.lookup_pid(dst_ip, src_port, dst_port)
        proc_dict = get_proc_info(pid)

        decision = self.enforcer.check_https(
            dst_ip=dst_ip,
            dst_port=dst_port,
            sni=sni,
            proc=ProcessInfo.from_dict(proc_dict),
            can_mitm=False,
        )

        proxy_logging.log_connection(
            type="https",
            dst_ip=dst_ip,
            dst_port=dst_port,
            host=sni,
            policy=decision.policy,
            error="tls_client_rejected_ca",
            **proc_dict,
            src_port=src_port,
            pid=pid,
        )
