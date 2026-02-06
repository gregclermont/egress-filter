"""Tests for MitmproxyAddon (proxy.handlers.mitmproxy)."""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.policy.enforcer import Decision, ProcessInfo, Verdict


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

class MockBPFState:
    """Minimal BPFState mock with configurable PID lookup."""

    def __init__(self, pid=1234):
        self._pid = pid
        self.dns_cache = {}

    def lookup_pid(self, dst_ip, src_port, dst_port, protocol=6):
        return self._pid


def _make_decision(allowed, rule_idx=0):
    """Create a real Decision object."""
    if allowed:
        return Decision(
            verdict=Verdict.ALLOW,
            reason=f"Matched rule {rule_idx}",
            matched_rule=rule_idx,
        )
    return Decision(
        verdict=Verdict.BLOCK,
        reason="No matching rule",
        matched_rule=None,
    )


# -- Flow factories (SimpleNamespace-based, matching dump tool output) --

def make_tls_clienthello_data(sni="example.com", dst_ip="93.184.216.34",
                               dst_port=443, src_port=54321):
    """Create a tls.ClientHelloData-like object."""
    data = SimpleNamespace(
        context=SimpleNamespace(
            client=SimpleNamespace(peername=("127.0.0.1", src_port)),
            server=SimpleNamespace(address=(dst_ip, dst_port)),
        ),
        client_hello=SimpleNamespace(sni=sni),
        ignore_connection=False,
    )
    return data


def make_http_flow(url="http://example.com/path", method="GET",
                   dst_ip="93.184.216.34", dst_port=80, src_port=54321):
    """Create an http.HTTPFlow-like object."""
    flow = SimpleNamespace(
        client_conn=SimpleNamespace(peername=("127.0.0.1", src_port)),
        server_conn=SimpleNamespace(address=(dst_ip, dst_port)),
        request=SimpleNamespace(pretty_url=url, method=method),
        response=None,
    )
    return flow


def make_tcp_flow(dst_ip="93.184.216.34", dst_port=8080, src_port=54321):
    """Create a tcp.TCPFlow-like object."""
    flow = SimpleNamespace(
        client_conn=SimpleNamespace(peername=("127.0.0.1", src_port)),
        server_conn=SimpleNamespace(address=(dst_ip, dst_port)),
    )
    flow.kill = MagicMock()
    return flow


def make_dns_flow(query_name="example.com", txid=0x1234, src_port=54321,
                  flow_id="test-flow-id"):
    """Create a dns.DNSFlow-like object for dns_request."""
    question = SimpleNamespace(name=query_name, type=1, class_=1)
    flow = SimpleNamespace(
        id=flow_id,
        client_conn=SimpleNamespace(peername=("127.0.0.1", src_port)),
        request=SimpleNamespace(
            id=txid,
            questions=[question],
            op_code=0,
            recursion_desired=True,
        ),
        response=None,
    )
    return flow


def make_dns_flow_with_response(query_name="example.com", answers=None,
                                flow_id="test-flow-id"):
    """Create a dns.DNSFlow-like object for dns_response."""
    question = SimpleNamespace(name=query_name, type=1, class_=1)
    flow = SimpleNamespace(
        id=flow_id,
        request=SimpleNamespace(
            id=0x1234,
            questions=[question],
        ),
        response=SimpleNamespace(answers=answers or []),
    )
    return flow


def make_dns_answer(ip="93.184.216.34", ttl=300, record_type=1):
    """Create a DNS answer record."""
    answer = SimpleNamespace(type=record_type, ttl=ttl)
    if record_type == 1:  # A record
        answer.ipv4_address = ip
    elif record_type == 28:  # AAAA record
        answer.ipv6_address = ip
    return answer


def make_tls_data(sni="example.com", dst_ip="93.184.216.34", dst_port=443,
                  src_port=54321):
    """Create a tls.TlsData-like object for tls_failed_client."""
    data = SimpleNamespace(
        context=SimpleNamespace(
            client=SimpleNamespace(
                peername=("127.0.0.1", src_port),
                sni=sni,
            ),
            server=SimpleNamespace(address=(dst_ip, dst_port)),
        ),
    )
    return data


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PROC_DICT = {"exe": "/usr/bin/curl", "cgroup": "/system.slice/runner.service"}


@pytest.fixture
def enforcer():
    """Mock PolicyEnforcer."""
    mock = MagicMock()
    mock.check_https.return_value = _make_decision(True)
    mock.check_http.return_value = _make_decision(True)
    mock.check_tcp.return_value = _make_decision(True)
    mock.check_dns.return_value = _make_decision(True)
    mock.check_udp.return_value = _make_decision(True)
    return mock


@pytest.fixture
def bpf():
    return MockBPFState(pid=1234)


@pytest.fixture
def addon(bpf, enforcer):
    """Create MitmproxyAddon with mocked dependencies."""
    with patch("proxy.handlers.mitmproxy.get_proc_info", return_value=dict(PROC_DICT)), \
         patch("proxy.handlers.mitmproxy.is_container_process", return_value=False), \
         patch("proxy.handlers.mitmproxy.proxy_logging") as mock_logging:
        mock_logging.log_connection = MagicMock()
        mock_logging.logger = MagicMock()

        from proxy.handlers.mitmproxy import MitmproxyAddon
        a = MitmproxyAddon(bpf, enforcer)
        # Stash references for assertions
        a._mock_log_connection = mock_logging.log_connection
        a._mock_logger = mock_logging.logger
        yield a


def _make_addon(bpf, enforcer, proc_dict=None, is_container=False, socket_dev=None):
    """Helper: create addon with specific proc/container config.

    Returns (addon, log_connection_mock, logger_mock).
    """
    if proc_dict is None:
        proc_dict = dict(PROC_DICT)

    with patch("proxy.handlers.mitmproxy.get_proc_info", return_value=proc_dict) as gpi, \
         patch("proxy.handlers.mitmproxy.is_container_process", return_value=is_container) as icp, \
         patch("proxy.handlers.mitmproxy.proxy_logging") as mock_logging:
        mock_logging.log_connection = MagicMock()
        mock_logging.logger = MagicMock()

        from proxy.handlers.mitmproxy import MitmproxyAddon
        a = MitmproxyAddon(bpf, enforcer, socket_dev=socket_dev)
        yield a, mock_logging.log_connection, mock_logging.logger, gpi, icp


# ---------------------------------------------------------------------------
# Tests: tls_clienthello
# ---------------------------------------------------------------------------

class TestTlsClienthello:
    """Tests for tls_clienthello hook."""

    def test_container_sni_allowed_passthrough(self, bpf, enforcer):
        """Container + SNI + allowed -> log, ignore_connection=True."""
        enforcer.check_https.return_value = _make_decision(True)
        gen = _make_addon(bpf, enforcer, is_container=True)
        addon, log_conn, logger, _, _ = next(gen)

        data = make_tls_clienthello_data(sni="example.com")
        addon.tls_clienthello(data)

        # Should passthrough (ignore MITM)
        assert data.ignore_connection is True
        # Should log the connection
        log_conn.assert_called_once()
        call_kw = log_conn.call_args.kwargs
        assert call_kw["type"] == "https"
        assert call_kw["host"] == "example.com"
        assert call_kw["policy"] == "allow"
        assert call_kw["pid"] == 1234

    def test_container_sni_blocked(self, bpf, enforcer):
        """Container + SNI + blocked -> log, client.error set."""
        enforcer.check_https.return_value = _make_decision(False)
        gen = _make_addon(bpf, enforcer, is_container=True)
        addon, log_conn, _, _, _ = next(gen)

        data = make_tls_clienthello_data(sni="evil.com")
        addon.tls_clienthello(data)

        # Should block
        assert data.context.client.error == "Blocked by egress policy"
        # Should log with deny
        log_conn.assert_called_once()
        assert log_conn.call_args.kwargs["policy"] == "deny"

    def test_noncontainer_sni_allowed_mitm(self, bpf, enforcer):
        """Non-container + SNI + allowed -> no log (defers to request()), can_mitm=True."""
        enforcer.check_https.return_value = _make_decision(True)
        gen = _make_addon(bpf, enforcer, is_container=False)
        addon, log_conn, _, _, _ = next(gen)

        data = make_tls_clienthello_data(sni="example.com")
        addon.tls_clienthello(data)

        # Should NOT passthrough (will MITM)
        assert data.ignore_connection is False
        # Should NOT log at this stage (deferred to request())
        log_conn.assert_not_called()
        # Enforcer called with can_mitm=True
        enforcer.check_https.assert_called_once()
        call_kw = enforcer.check_https.call_args.kwargs
        assert call_kw["can_mitm"] is True

    def test_noncontainer_sni_blocked(self, bpf, enforcer):
        """Non-container + SNI + blocked -> log, client.error set."""
        enforcer.check_https.return_value = _make_decision(False)
        gen = _make_addon(bpf, enforcer, is_container=False)
        addon, log_conn, _, _, _ = next(gen)

        data = make_tls_clienthello_data(sni="evil.com")
        addon.tls_clienthello(data)

        assert data.context.client.error == "Blocked by egress policy"
        log_conn.assert_called_once()
        assert log_conn.call_args.kwargs["policy"] == "deny"

    def test_noncontainer_no_sni_defers(self, bpf, enforcer):
        """Non-container + no SNI -> no enforcement (defers to request())."""
        gen = _make_addon(bpf, enforcer, is_container=False)
        addon, log_conn, _, _, _ = next(gen)

        data = make_tls_clienthello_data(sni=None)
        addon.tls_clienthello(data)

        # No enforcement at TLS stage
        enforcer.check_https.assert_not_called()
        log_conn.assert_not_called()
        assert data.ignore_connection is False

    def test_container_no_sni_enforces(self, bpf, enforcer):
        """Container + no SNI -> enforces (can't decrypt), passthrough."""
        enforcer.check_https.return_value = _make_decision(True)
        gen = _make_addon(bpf, enforcer, is_container=True)
        addon, log_conn, _, _, _ = next(gen)

        data = make_tls_clienthello_data(sni=None)
        addon.tls_clienthello(data)

        # Should enforce since it's a container (can't MITM)
        enforcer.check_https.assert_called_once()
        assert data.ignore_connection is True

    def test_pid_not_found(self, enforcer):
        """PID not found -> still enforces with empty proc_dict."""
        bpf = MockBPFState(pid=None)
        gen = _make_addon(bpf, enforcer, proc_dict={}, is_container=False)
        addon, log_conn, _, _, icp = next(gen)

        data = make_tls_clienthello_data(sni="example.com")
        addon.tls_clienthello(data)

        # is_container_process should not be called when pid is None
        icp.assert_not_called()
        # sni is present, so should_enforce_now is True -> enforces
        enforcer.check_https.assert_called_once()

    def test_log_includes_proc_and_connection_info(self, bpf, enforcer):
        """Log entry includes proc info fields, pid, and src_port."""
        enforcer.check_https.return_value = _make_decision(True)
        gen = _make_addon(bpf, enforcer, is_container=True,
                          proc_dict={"exe": "/usr/bin/curl", "cgroup": "/test"})
        addon, log_conn, _, _, _ = next(gen)

        data = make_tls_clienthello_data(sni="example.com", src_port=12345)
        addon.tls_clienthello(data)

        kw = log_conn.call_args.kwargs
        assert kw["exe"] == "/usr/bin/curl"
        assert kw["cgroup"] == "/test"
        assert kw["pid"] == 1234
        assert kw["src_port"] == 12345
        assert kw["dst_ip"] == "93.184.216.34"
        assert kw["dst_port"] == 443


# ---------------------------------------------------------------------------
# Tests: request
# ---------------------------------------------------------------------------

class TestRequest:
    """Tests for request hook (HTTP/HTTPS after MITM)."""

    def test_http_allowed(self, bpf, enforcer):
        """HTTP allowed -> log with type=http, no response set."""
        enforcer.check_http.return_value = _make_decision(True)
        gen = _make_addon(bpf, enforcer)
        addon, log_conn, _, _, _ = next(gen)

        flow = make_http_flow(url="http://example.com/path", method="GET")
        addon.request(flow)

        assert flow.response is None
        log_conn.assert_called_once()
        kw = log_conn.call_args.kwargs
        assert kw["type"] == "http"
        assert kw["url"] == "http://example.com/path"
        assert kw["method"] == "GET"
        assert kw["policy"] == "allow"

    def test_http_blocked(self, bpf, enforcer):
        """HTTP blocked -> log with policy=deny, 403 response."""
        enforcer.check_http.return_value = _make_decision(False)
        gen = _make_addon(bpf, enforcer)
        addon, log_conn, _, _, _ = next(gen)

        flow = make_http_flow(url="http://evil.com/", method="POST")
        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        log_conn.assert_called_once()
        assert log_conn.call_args.kwargs["policy"] == "deny"

    def test_https_mitmed(self, bpf, enforcer):
        """HTTPS (MITMed) -> log with type=https."""
        enforcer.check_http.return_value = _make_decision(True)
        gen = _make_addon(bpf, enforcer)
        addon, log_conn, _, _, _ = next(gen)

        flow = make_http_flow(url="https://example.com/secure", method="GET",
                              dst_port=443)
        addon.request(flow)

        kw = log_conn.call_args.kwargs
        assert kw["type"] == "https"

    def test_enforcer_called_with_correct_args(self, bpf, enforcer):
        """Enforcer called with correct dst_ip, dst_port, url, method, ProcessInfo."""
        enforcer.check_http.return_value = _make_decision(True)
        gen = _make_addon(bpf, enforcer, proc_dict={"exe": "/usr/bin/wget"})
        addon, _, _, _, _ = next(gen)

        flow = make_http_flow(url="http://example.com/api", method="POST",
                              dst_ip="10.0.0.1", dst_port=8080)
        addon.request(flow)

        enforcer.check_http.assert_called_once()
        kw = enforcer.check_http.call_args.kwargs
        assert kw["dst_ip"] == "10.0.0.1"
        assert kw["dst_port"] == 8080
        assert kw["url"] == "http://example.com/api"
        assert kw["method"] == "POST"
        assert isinstance(kw["proc"], ProcessInfo)
        assert kw["proc"].exe == "/usr/bin/wget"

    def test_http_blocked_only_logs_once(self, bpf, enforcer):
        """Blocked HTTP request should log exactly once."""
        enforcer.check_http.return_value = _make_decision(False)
        gen = _make_addon(bpf, enforcer)
        addon, log_conn, _, _, _ = next(gen)

        flow = make_http_flow(url="http://evil.com/")
        addon.request(flow)

        assert log_conn.call_count == 1


# ---------------------------------------------------------------------------
# Tests: tcp_start
# ---------------------------------------------------------------------------

class TestTcpStart:
    """Tests for tcp_start hook."""

    def test_allowed(self, bpf, enforcer):
        """Allowed TCP -> log, not killed."""
        enforcer.check_tcp.return_value = _make_decision(True)
        gen = _make_addon(bpf, enforcer)
        addon, log_conn, _, _, _ = next(gen)

        flow = make_tcp_flow(dst_ip="10.0.0.1", dst_port=8080)
        addon.tcp_start(flow)

        flow.kill.assert_not_called()
        log_conn.assert_called_once()
        kw = log_conn.call_args.kwargs
        assert kw["type"] == "tcp"
        assert kw["policy"] == "allow"

    def test_blocked(self, bpf, enforcer):
        """Blocked TCP -> log, flow.kill() called."""
        enforcer.check_tcp.return_value = _make_decision(False)
        gen = _make_addon(bpf, enforcer)
        addon, log_conn, _, _, _ = next(gen)

        flow = make_tcp_flow()
        addon.tcp_start(flow)

        flow.kill.assert_called_once()
        log_conn.assert_called_once()
        assert log_conn.call_args.kwargs["policy"] == "deny"


# ---------------------------------------------------------------------------
# Tests: dns_request
# ---------------------------------------------------------------------------

class TestDnsRequest:
    """Tests for dns_request hook."""

    def test_cache_hit_allowed(self, bpf, enforcer):
        """Cache hit + allowed -> log, stash in _pending_dns."""
        enforcer.check_dns.return_value = _make_decision(True)
        gen = _make_addon(bpf, enforcer)
        addon, log_conn, _, _, _ = next(gen)

        # Populate dns_cache (as nfqueue would)
        bpf.dns_cache[(54321, 0x1234)] = (1234, "8.8.8.8", 53)

        flow = make_dns_flow(query_name="example.com", txid=0x1234,
                             src_port=54321, flow_id="flow-1")
        addon.dns_request(flow)

        # Should log
        log_conn.assert_called_once()
        kw = log_conn.call_args.kwargs
        assert kw["type"] == "dns"
        assert kw["name"] == "example.com"
        assert kw["policy"] == "allow"
        assert kw["dst_ip"] == "8.8.8.8"
        assert kw["dst_port"] == 53

        # Should stash for dns_response
        assert "flow-1" in addon._pending_dns

        # Cache entry consumed
        assert (54321, 0x1234) not in bpf.dns_cache

    def test_cache_hit_blocked(self, bpf, enforcer):
        """Cache hit + blocked -> log, REFUSED response, NOT stashed."""
        enforcer.check_dns.return_value = _make_decision(False)
        gen = _make_addon(bpf, enforcer)
        addon, log_conn, _, _, _ = next(gen)

        bpf.dns_cache[(54321, 0x1234)] = (1234, "8.8.8.8", 53)

        flow = make_dns_flow(query_name="evil.com", txid=0x1234,
                             src_port=54321, flow_id="flow-2")
        addon.dns_request(flow)

        # Should set REFUSED response
        assert flow.response is not None
        assert flow.response.response_code == 5

        # Should log with deny
        log_conn.assert_called_once()
        assert log_conn.call_args.kwargs["policy"] == "deny"

        # Should NOT stash
        assert "flow-2" not in addon._pending_dns

    def test_cache_miss(self, bpf, enforcer):
        """Cache miss -> logger.error, no enforcement."""
        gen = _make_addon(bpf, enforcer)
        addon, log_conn, logger, _, _ = next(gen)

        # No dns_cache entry
        flow = make_dns_flow(query_name="unknown.com", txid=0xAAAA,
                             src_port=55555)
        addon.dns_request(flow)

        # Should log error
        logger.error.assert_called_once()
        assert "DNS cache miss" in logger.error.call_args[0][0]

        # Should NOT call enforcer or log connection
        enforcer.check_dns.assert_not_called()
        log_conn.assert_not_called()

    def test_uses_original_4tuple(self, bpf, enforcer):
        """Uses original 4-tuple from nfqueue cache (pre-NAT dst_ip/dst_port)."""
        enforcer.check_dns.return_value = _make_decision(True)
        gen = _make_addon(bpf, enforcer)
        addon, log_conn, _, _, _ = next(gen)

        # nfqueue cached original destination (before NAT redirect to 127.0.0.1:8053)
        bpf.dns_cache[(54321, 0x1234)] = (1234, "168.63.129.16", 53)

        flow = make_dns_flow(query_name="example.com", txid=0x1234,
                             src_port=54321)
        addon.dns_request(flow)

        # Enforcer should get original dst_ip/dst_port, not NAT'd
        kw = enforcer.check_dns.call_args.kwargs
        assert kw["dst_ip"] == "168.63.129.16"
        assert kw["dst_port"] == 53


# ---------------------------------------------------------------------------
# Tests: dns_response
# ---------------------------------------------------------------------------

class TestDnsResponse:
    """Tests for dns_response hook."""

    def test_a_record_records_ips(self, bpf, enforcer):
        """A record answers -> record_dns_response called with IPs and min TTL."""
        gen = _make_addon(bpf, enforcer)
        addon, log_conn, _, _, _ = next(gen)

        # Stash pending context (as dns_request would)
        addon._pending_dns["flow-1"] = dict(
            dst_ip="8.8.8.8", dst_port=53, name="example.com",
            policy="allow", src_port=54321, pid=1234,
        )

        answers = [
            make_dns_answer(ip="93.184.216.34", ttl=300),
            make_dns_answer(ip="93.184.216.35", ttl=200),
        ]
        flow = make_dns_flow_with_response("example.com", answers, flow_id="flow-1")
        addon.dns_response(flow)

        # Should call record_dns_response
        enforcer.record_dns_response.assert_called_once_with(
            "example.com", ["93.184.216.34", "93.184.216.35"], 200
        )

        # Should log dns_response event
        log_conn.assert_called_once()
        kw = log_conn.call_args.kwargs
        assert kw["type"] == "dns_response"
        assert kw["answers"] == ["93.184.216.34", "93.184.216.35"]
        assert kw["ttl"] == 200

    def test_no_response_noop(self, bpf, enforcer):
        """No response -> no-op."""
        gen = _make_addon(bpf, enforcer)
        addon, log_conn, _, _, _ = next(gen)

        flow = SimpleNamespace(
            id="flow-1",
            request=SimpleNamespace(questions=[SimpleNamespace(name="example.com")]),
            response=None,
        )
        addon.dns_response(flow)

        enforcer.record_dns_response.assert_not_called()
        log_conn.assert_not_called()

    def test_no_pending_context_still_records(self, bpf, enforcer):
        """No pending context -> still records IPs, but no log event."""
        gen = _make_addon(bpf, enforcer)
        addon, log_conn, _, _, _ = next(gen)

        answers = [make_dns_answer(ip="1.2.3.4", ttl=60)]
        flow = make_dns_flow_with_response("test.com", answers, flow_id="no-pending")
        addon.dns_response(flow)

        # IPs still recorded
        enforcer.record_dns_response.assert_called_once()
        # But no connection log (no pending context)
        log_conn.assert_not_called()

    def test_min_ttl_used(self, bpf, enforcer):
        """Multiple TTLs -> minimum is used."""
        gen = _make_addon(bpf, enforcer)
        addon, log_conn, _, _, _ = next(gen)

        addon._pending_dns["flow-1"] = dict(
            dst_ip="8.8.8.8", dst_port=53, name="multi.com",
            policy="allow", src_port=54321, pid=1234,
        )

        answers = [
            make_dns_answer(ip="1.1.1.1", ttl=500),
            make_dns_answer(ip="2.2.2.2", ttl=100),
            make_dns_answer(ip="3.3.3.3", ttl=300),
        ]
        flow = make_dns_flow_with_response("multi.com", answers, flow_id="flow-1")
        addon.dns_response(flow)

        # Should use minimum TTL
        enforcer.record_dns_response.assert_called_once_with(
            "multi.com", ["1.1.1.1", "2.2.2.2", "3.3.3.3"], 100
        )

    def test_no_answers_no_record(self, bpf, enforcer):
        """Empty answers -> no record_dns_response call."""
        gen = _make_addon(bpf, enforcer)
        addon, log_conn, _, _, _ = next(gen)

        flow = make_dns_flow_with_response("empty.com", answers=[], flow_id="flow-1")
        addon.dns_response(flow)

        enforcer.record_dns_response.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: tls_failed_client
# ---------------------------------------------------------------------------

class TestTlsFailedClient:
    """Tests for tls_failed_client hook."""

    def test_logs_tls_rejection(self, bpf, enforcer):
        """Logs with error=tls_client_rejected_ca."""
        gen = _make_addon(bpf, enforcer)
        addon, log_conn, _, _, _ = next(gen)

        data = make_tls_data(sni="strict.com", dst_ip="10.0.0.1", dst_port=443,
                             src_port=12345)
        addon.tls_failed_client(data)

        log_conn.assert_called_once()
        kw = log_conn.call_args.kwargs
        assert kw["type"] == "https"
        assert kw["host"] == "strict.com"
        assert kw["error"] == "tls_client_rejected_ca"
        assert kw["dst_ip"] == "10.0.0.1"
        assert kw["pid"] == 1234
        assert kw["src_port"] == 12345


# ---------------------------------------------------------------------------
# Tests: Socket.dev integration
# ---------------------------------------------------------------------------

class TestSocketDevIntegration:
    """Tests for Socket.dev package security check in request() hook."""

    def test_malicious_package_blocked(self, bpf, enforcer):
        """Registry URL for malicious package -> 403 with security_block log."""
        enforcer.check_http.return_value = _make_decision(True)

        socket_dev = MagicMock()
        socket_dev.check.return_value = MagicMock(blocked=True, reasons=["malware"])

        gen = _make_addon(bpf, enforcer, socket_dev=socket_dev)
        addon, log_conn, _, _, _ = next(gen)

        flow = make_http_flow(
            url="https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz",
            method="GET",
            dst_port=443,
        )
        addon.request(flow)

        # Should block with 403
        assert flow.response is not None
        assert flow.response.status_code == 403
        assert b"Socket.dev" in flow.response.content

        # Should log with security_block
        log_conn.assert_called_once()
        kw = log_conn.call_args.kwargs
        assert kw["policy"] == "deny"
        assert kw["security_block"] is True
        assert kw["purl"] == "pkg:npm/evil-pkg@1.0.0"

    def test_clean_package_allowed(self, bpf, enforcer):
        """Registry URL for clean package -> allowed normally."""
        enforcer.check_http.return_value = _make_decision(True)

        socket_dev = MagicMock()
        socket_dev.check.return_value = MagicMock(blocked=False, reasons=[])

        gen = _make_addon(bpf, enforcer, socket_dev=socket_dev)
        addon, log_conn, _, _, _ = next(gen)

        flow = make_http_flow(
            url="https://registry.npmjs.org/express/-/express-4.18.2.tgz",
            method="GET",
            dst_port=443,
        )
        addon.request(flow)

        assert flow.response is None
        log_conn.assert_called_once()
        assert log_conn.call_args.kwargs["policy"] == "allow"

    def test_non_registry_url_skipped(self, bpf, enforcer):
        """Non-registry URL -> no socket_dev check, allowed normally."""
        enforcer.check_http.return_value = _make_decision(True)

        socket_dev = MagicMock()

        gen = _make_addon(bpf, enforcer, socket_dev=socket_dev)
        addon, log_conn, _, _, _ = next(gen)

        flow = make_http_flow(url="https://example.com/api/data", method="GET")
        addon.request(flow)

        socket_dev.check.assert_not_called()
        assert flow.response is None

    def test_socket_dev_none_result_allows(self, bpf, enforcer):
        """socket_dev.check returns None (API error) -> fail-open, allow."""
        enforcer.check_http.return_value = _make_decision(True)

        socket_dev = MagicMock()
        socket_dev.check.return_value = None

        gen = _make_addon(bpf, enforcer, socket_dev=socket_dev)
        addon, log_conn, _, _, _ = next(gen)

        flow = make_http_flow(
            url="https://registry.npmjs.org/express/-/express-4.18.2.tgz",
            method="GET",
            dst_port=443,
        )
        addon.request(flow)

        assert flow.response is None
        log_conn.assert_called_once()
        assert log_conn.call_args.kwargs["policy"] == "allow"

    def test_no_socket_dev_client_skips_check(self, bpf, enforcer):
        """No socket_dev client -> no check, normal flow."""
        enforcer.check_http.return_value = _make_decision(True)

        gen = _make_addon(bpf, enforcer, socket_dev=None)
        addon, log_conn, _, _, _ = next(gen)

        flow = make_http_flow(
            url="https://registry.npmjs.org/express/-/express-4.18.2.tgz",
            method="GET",
            dst_port=443,
        )
        addon.request(flow)

        assert flow.response is None

    def test_policy_deny_takes_precedence(self, bpf, enforcer):
        """Policy denies before socket_dev is checked."""
        enforcer.check_http.return_value = _make_decision(False)

        socket_dev = MagicMock()

        gen = _make_addon(bpf, enforcer, socket_dev=socket_dev)
        addon, log_conn, _, _, _ = next(gen)

        flow = make_http_flow(
            url="https://registry.npmjs.org/express/-/express-4.18.2.tgz",
            method="GET",
            dst_port=443,
        )
        addon.request(flow)

        # Policy blocked it, socket_dev never called
        socket_dev.check.assert_not_called()
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_pypi_package_checked(self, bpf, enforcer):
        """PyPI package URL -> socket_dev check called with correct PURL."""
        enforcer.check_http.return_value = _make_decision(True)

        socket_dev = MagicMock()
        socket_dev.check.return_value = MagicMock(blocked=False, reasons=[])

        gen = _make_addon(bpf, enforcer, socket_dev=socket_dev)
        addon, log_conn, _, _, _ = next(gen)

        flow = make_http_flow(
            url="https://files.pythonhosted.org/packages/ab/cd/requests-2.31.0.tar.gz",
            method="GET",
            dst_port=443,
        )
        addon.request(flow)

        socket_dev.check.assert_called_once_with("pkg:pypi/requests@2.31.0")
