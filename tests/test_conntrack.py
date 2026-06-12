"""Tests for the conntrack NAT-reversal module (fail-safe behavior).

The real netlink query path needs root + a live connection, so these focus
on the contract that matters operationally: the module never raises, and
degrades to "unavailable -> None" when the library can't be used.
"""

from proxy import conntrack
from proxy.conntrack import ConntrackReverser


def test_unavailable_when_library_missing(monkeypatch):
    def boom(*a, **k):
        raise OSError("no library")

    monkeypatch.setattr(conntrack.ctypes, "CDLL", boom)
    r = ConntrackReverser()
    assert r.available is False
    # Queries must be safe no-ops when unavailable.
    assert r.original_src_port(("127.0.0.1", 8080), ("10.0.0.1", 9999)) is None
    r.close()


def test_query_never_raises_on_real_or_unavailable_lib():
    # Whether or not the lib/handle is usable in this environment, a query
    # must return an int or None and never propagate an exception.
    r = ConntrackReverser()
    result = r.original_src_port(("127.0.0.1", 8080), ("10.255.255.254", 65000))
    assert result is None or isinstance(result, int)
    r.close()


def test_close_is_idempotent():
    r = ConntrackReverser()
    r.close()
    r.close()  # must not raise
