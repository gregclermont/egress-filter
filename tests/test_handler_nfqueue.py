"""Tests for NfqueueHandler (proxy.handlers.nfqueue)."""

import sys
from pathlib import Path
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


class MockNfPacket:
    """Mock nfqueue packet tracking set_mark, repeat, and drop calls."""

    def __init__(self, payload: bytes):
        self._payload = payload
        self.marks = []
        self.repeated = False
        self.dropped = False

    def get_payload(self) -> bytes:
        return self._payload

    def set_mark(self, mark: int) -> None:
        self.marks.append(mark)

    def repeat(self) -> None:
        self.repeated = True

    def drop(self) -> None:
        self.dropped = True


def _make_dns_packet(src_ip="10.0.0.1", dst_ip="8.8.8.8",
                     sport=54321, dport=53, txid=0x1234) -> bytes:
    """Build a raw DNS query packet using scapy."""
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, UDP

    pkt = (
        IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=dport)
        / DNS(id=txid, qr=0, qd=DNSQR(qname="example.com"))
    )
    return bytes(pkt)


def _make_udp_packet(src_ip="10.0.0.1", dst_ip="192.168.1.100",
                     sport=54321, dport=9999, payload=b"hello") -> bytes:
    """Build a raw non-DNS UDP packet using scapy."""
    from scapy.layers.inet import IP, UDP

    pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / payload
    return bytes(pkt)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PROC_DICT = {"exe": "/usr/bin/curl", "cgroup": "/system.slice/runner.service"}


@pytest.fixture
def enforcer():
    """Mock PolicyEnforcer."""
    mock = MagicMock()
    mock.check_udp.return_value = _make_decision(True)
    return mock


@pytest.fixture
def bpf():
    return MockBPFState(pid=1234)


def _make_handler(bpf, enforcer, proc_dict=None):
    """Create NfqueueHandler with mocked dependencies.

    Returns (handler, log_connection_mock, logger_mock).
    """
    if proc_dict is None:
        proc_dict = dict(PROC_DICT)

    with patch("proxy.handlers.nfqueue.get_proc_info", return_value=proc_dict), \
         patch("proxy.handlers.nfqueue.proxy_logging") as mock_logging:
        mock_logging.log_connection = MagicMock()
        mock_logging.logger = MagicMock()

        from proxy.handlers.nfqueue import NfqueueHandler
        handler = NfqueueHandler(bpf, enforcer)
        yield handler, mock_logging.log_connection, mock_logging.logger


# ---------------------------------------------------------------------------
# Tests: handle_packet
# ---------------------------------------------------------------------------

class TestHandlePacket:
    """Tests for NfqueueHandler.handle_packet."""

    def test_dns_packet_redirected(self, bpf, enforcer):
        """DNS packet -> mark=2 (MARK_DNS_REDIRECT), repeat(), dns_cache populated."""
        gen = _make_handler(bpf, enforcer)
        handler, log_conn, _ = next(gen)

        raw = _make_dns_packet(sport=54321, dport=53, txid=0xABCD)
        pkt = MockNfPacket(raw)
        handler.handle_packet(pkt)

        # Mark for DNS redirect
        assert pkt.marks == [2]  # MARK_DNS_REDIRECT
        assert pkt.repeated is True
        assert pkt.dropped is False

        # dns_cache populated with (pid, dst_ip, dst_port)
        cache_key = (54321, 0xABCD)
        assert cache_key in bpf.dns_cache
        pid, dst_ip, dst_port = bpf.dns_cache[cache_key]
        assert pid == 1234
        assert dst_ip == "8.8.8.8"
        assert dst_port == 53

        # DNS packets are NOT logged here (logged by mitmproxy's dns_request)
        log_conn.assert_not_called()

    def test_non_dns_udp_allowed(self, bpf, enforcer):
        """Non-DNS UDP allowed -> mark=4 (MARK_FASTPATH), repeat()."""
        enforcer.check_udp.return_value = _make_decision(True)
        gen = _make_handler(bpf, enforcer)
        handler, log_conn, _ = next(gen)

        raw = _make_udp_packet(dst_ip="192.168.1.100", dport=9999)
        pkt = MockNfPacket(raw)
        handler.handle_packet(pkt)

        assert pkt.marks == [4]  # MARK_FASTPATH
        assert pkt.repeated is True
        assert pkt.dropped is False

        # Should log
        log_conn.assert_called_once()
        kw = log_conn.call_args.kwargs
        assert kw["type"] == "udp"
        assert kw["dst_ip"] == "192.168.1.100"
        assert kw["dst_port"] == 9999
        assert kw["policy"] == "allow"
        assert kw["pid"] == 1234

    def test_non_dns_udp_blocked(self, bpf, enforcer):
        """Non-DNS UDP blocked -> drop(), no repeat()."""
        enforcer.check_udp.return_value = _make_decision(False)
        gen = _make_handler(bpf, enforcer)
        handler, log_conn, _ = next(gen)

        raw = _make_udp_packet()
        pkt = MockNfPacket(raw)
        handler.handle_packet(pkt)

        assert pkt.dropped is True
        assert pkt.repeated is False
        # No marks set on drop
        assert pkt.marks == []

        # Should log with deny
        log_conn.assert_called_once()
        assert log_conn.call_args.kwargs["policy"] == "deny"

    def test_packet_count_incremented(self, bpf, enforcer):
        """Packet count incremented per packet."""
        gen = _make_handler(bpf, enforcer)
        handler, _, _ = next(gen)

        assert handler.packet_count == 0

        raw = _make_udp_packet()
        handler.handle_packet(MockNfPacket(raw))
        assert handler.packet_count == 1

        handler.handle_packet(MockNfPacket(raw))
        assert handler.packet_count == 2

    def test_dns_no_enforcer_call(self, bpf, enforcer):
        """Enforcer NOT called for DNS (policy checked in mitmproxy, not nfqueue)."""
        gen = _make_handler(bpf, enforcer)
        handler, _, _ = next(gen)

        raw = _make_dns_packet()
        handler.handle_packet(MockNfPacket(raw))

        enforcer.check_udp.assert_not_called()

    def test_non_dns_log_includes_correct_fields(self, bpf, enforcer):
        """Log entry for non-DNS includes type=udp and correct fields."""
        enforcer.check_udp.return_value = _make_decision(True)
        gen = _make_handler(bpf, enforcer, proc_dict={"exe": "/usr/bin/app"})
        handler, log_conn, _ = next(gen)

        raw = _make_udp_packet(src_ip="10.0.0.5", dst_ip="172.16.0.1",
                               sport=33333, dport=5000)
        handler.handle_packet(MockNfPacket(raw))

        kw = log_conn.call_args.kwargs
        assert kw["type"] == "udp"
        assert kw["dst_ip"] == "172.16.0.1"
        assert kw["dst_port"] == 5000
        assert kw["src_port"] == 33333
        assert kw["pid"] == 1234
        assert kw["exe"] == "/usr/bin/app"

    def test_enforcer_receives_process_info(self, bpf, enforcer):
        """Enforcer called with ProcessInfo from proc_dict."""
        enforcer.check_udp.return_value = _make_decision(True)
        gen = _make_handler(bpf, enforcer, proc_dict={"exe": "/usr/bin/app", "cgroup": "/test"})
        handler, _, _ = next(gen)

        raw = _make_udp_packet()
        handler.handle_packet(MockNfPacket(raw))

        enforcer.check_udp.assert_called_once()
        kw = enforcer.check_udp.call_args.kwargs
        assert isinstance(kw["proc"], ProcessInfo)
        assert kw["proc"].exe == "/usr/bin/app"
        assert kw["proc"].cgroup == "/test"
