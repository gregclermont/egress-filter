"""Tests for NAT-aware PID lookup (conntrack source-port reversal).

These exercise the BPFState.lookup_pid_nat_aware logic with a fake BPF map
and a fake conntrack reverser — no kernel / netlink required.
"""

from proxy.bpf import BPFState, ConnKeyV4
from proxy.utils import ip_to_int, IPPROTO_TCP


class FakeMap:
    """In-memory stand-in for the typed BPF map keyed by ConnKeyV4."""

    def __init__(self):
        self._d = {}

    def put(self, dst_ip, src_port, dst_port, pid, protocol=IPPROTO_TCP):
        self._d[(ip_to_int(dst_ip), src_port, dst_port, protocol)] = pid

    def get(self, key: ConnKeyV4):
        return self._d.get((key.dst_ip, key.src_port, key.dst_port, key.protocol))


class FakeReverser:
    """Stand-in for ConntrackReverser returning a preset original port."""

    def __init__(self, orig_port=None):
        self.orig_port = orig_port
        self.calls = []

    def original_src_port(self, client, orig_dst, protocol=IPPROTO_TCP):
        self.calls.append((client, orig_dst, protocol))
        return self.orig_port


def _bpf(fake_map, reverser=None):
    b = BPFState.__new__(BPFState)  # bypass __init__ (no real BPF load)
    b.map_v4 = fake_map
    b.conntrack = reverser
    return b


def test_direct_hit_no_conntrack_needed():
    m = FakeMap()
    m.put("140.82.113.3", 41000, 443, pid=1234)
    rev = FakeReverser(orig_port=41000)
    bpf = _bpf(m, rev)

    # peername src_port matches what was recorded -> direct hit, no reversal
    pid = bpf.lookup_pid_nat_aware(
        "140.82.113.3", 443, peername=("10.1.0.5", 41000),
    )
    assert pid == 1234
    assert rev.calls == []  # conntrack not consulted on a hit


def test_nat_remapped_recovered_via_conntrack():
    m = FakeMap()
    # kprobe recorded the ORIGINAL port 41000
    m.put("140.82.113.3", 41000, 443, pid=4321)
    # conntrack maps the connection back to original port 41000
    rev = FakeReverser(orig_port=41000)
    bpf = _bpf(m, rev)

    # proxy sees the MANGLED port 8957 -> direct lookup misses -> reversal hits
    pid = bpf.lookup_pid_nat_aware(
        "140.82.113.3", 443, peername=("10.1.0.5", 8957),
    )
    assert pid == 4321
    assert rev.calls == [(("10.1.0.5", 8957), ("140.82.113.3", 443), IPPROTO_TCP)]


def test_miss_with_no_conntrack_entry_returns_none():
    m = FakeMap()
    m.put("140.82.113.3", 41000, 443, pid=4321)
    rev = FakeReverser(orig_port=None)  # conntrack has no entry
    bpf = _bpf(m, rev)

    pid = bpf.lookup_pid_nat_aware(
        "140.82.113.3", 443, peername=("10.1.0.5", 8957),
    )
    assert pid is None


def test_reverser_returns_same_port_does_not_loop():
    # If conntrack returns the same (unmangled) port, we must not re-query.
    m = FakeMap()  # empty -> genuine miss
    rev = FakeReverser(orig_port=8957)
    bpf = _bpf(m, rev)

    pid = bpf.lookup_pid_nat_aware(
        "140.82.113.3", 443, peername=("10.1.0.5", 8957),
    )
    assert pid is None


def test_no_conntrack_reverser_falls_back_to_miss():
    m = FakeMap()
    bpf = _bpf(m, reverser=None)
    pid = bpf.lookup_pid_nat_aware(
        "140.82.113.3", 443, peername=("10.1.0.5", 8957),
    )
    assert pid is None


def test_no_peername_skips_reversal():
    m = FakeMap()
    m.put("140.82.113.3", 41000, 443, pid=4321)
    rev = FakeReverser(orig_port=41000)
    bpf = _bpf(m, rev)

    # Without a peername there's nothing to look up or reverse.
    pid = bpf.lookup_pid_nat_aware("140.82.113.3", 443, peername=None)
    assert pid is None
    assert rev.calls == []
