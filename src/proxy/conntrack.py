"""Conntrack-based NAT reversal for PID attribution.

The BPF `tcp_connect` kprobe records the connection 4-tuple using the
*original* (pre-NAT) source port. The transparent-proxy handler, however,
sees the connection *after* iptables REDIRECT, whose DNAT collapses every
destination onto the single proxy socket. Under load this triggers
netfilter source-port remapping, so the proxy's `peername` source port no
longer matches the port the kprobe recorded — the BPF lookup misses and the
connection can't be attributed.

This module reverses that translation. Conntrack is the only component that
knows the original<->remapped mapping, so on a BPF miss we ask it for the
*original* source port of the connection and the handler re-keys the lookup.

We identify the connection by the fields the proxy knows reliably and that
together uniquely pin a conntrack entry:
  - the original source IP and original destination (IP:port), from the
    accepted socket's peername and SO_ORIGINAL_DST;
  - the reply tuple's destination port = the (possibly NAT-mangled) source
    port the proxy sees (peername port).

We find that entry with a filtered table walk and read its original source
port. Matching on the original destination is what makes this safe: a
remapped reply port can be shared with an unrelated flow, but only one entry
has that reply port AND our original destination — so we can never return a
port belonging to a different destination (worst case: no match, and we
simply don't attribute, exactly as before this change).

Everything is fail-safe: if the library is missing or any query fails, calls
return None and attribution falls back to today's BPF-only behavior.
"""

from __future__ import annotations

import ctypes
import socket

from . import logging as proxy_logging
from .utils import ip_to_int, IPPROTO_TCP

# libnetfilter_conntrack constants (stable ABI).
_CONNTRACK = 1  # NFNL_SUBSYS_CTNETLINK

# enum nf_conntrack_attr
_ATTR_ORIG_IPV4_SRC = 0
_ATTR_ORIG_IPV4_DST = 1
_ATTR_ORIG_PORT_SRC = 8
_ATTR_ORIG_PORT_DST = 9
_ATTR_REPL_PORT_DST = 11

# enum nf_conntrack_query
_NFCT_Q_DUMP = 5

# enum nf_conntrack_msg_type (mask for callback registration)
_NFCT_T_ALL = 7  # NEW | UPDATE | DESTROY

# enum nf_conntrack_callback return values
_NFCT_CB_CONTINUE = 1
_NFCT_CB_STOP = 0

_AF_INET = socket.AF_INET

# C callback signature: int cb(enum msg_type, struct nf_conntrack *, void *data)
_CALLBACK_T = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p
)


class ConntrackReverser:
    """Recover the original source port of a NAT-mangled connection.

    Opens a single netlink handle and reuses it. Intended to be called from
    the (single-threaded) proxy event loop, only on the BPF-miss path.
    """

    def __init__(self):
        self._lib = None
        self._cb = _CALLBACK_T(self._on_entry)  # keep CFUNCTYPE alive
        self._criteria = None  # match dict for the in-progress dump
        self._result = None
        self.available = False
        try:
            self._setup()
            self.available = True
        except Exception as e:
            try:
                proxy_logging.logger.warning(
                    f"Conntrack NAT reversal unavailable ({e}); "
                    "attribution will fall back to BPF-only"
                )
            except Exception:
                pass

    def _setup(self):
        lib = ctypes.CDLL("libnetfilter_conntrack.so.3", use_errno=True)

        # Declare prototypes so 64-bit pointers aren't truncated to int.
        lib.nfct_open.restype = ctypes.c_void_p
        lib.nfct_open.argtypes = [ctypes.c_uint8, ctypes.c_uint]
        lib.nfct_close.argtypes = [ctypes.c_void_p]
        lib.nfct_get_attr_u16.restype = ctypes.c_uint16
        lib.nfct_get_attr_u16.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.nfct_get_attr_u32.restype = ctypes.c_uint32
        lib.nfct_get_attr_u32.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.nfct_callback_register.argtypes = [
            ctypes.c_void_p, ctypes.c_int, _CALLBACK_T, ctypes.c_void_p
        ]
        lib.nfct_query.restype = ctypes.c_int
        lib.nfct_query.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
        lib.nfct_fd.restype = ctypes.c_int
        lib.nfct_fd.argtypes = [ctypes.c_void_p]
        self._lib = lib

        # Verify we can actually open a conntrack handle (needs CAP_NET_ADMIN).
        h = lib.nfct_open(_CONNTRACK, 0)
        if not h:
            raise OSError("nfct_open failed")
        lib.nfct_close(h)

    def _on_entry(self, _msg_type, ct, _data):
        """Per-entry callback: capture the original source port of the entry
        matching all of our criteria (original src IP + original dst + reply
        port). Matching the original destination guarantees we never attribute
        a port belonging to a different flow that reused the reply port."""
        try:
            lib = self._lib
            m = self._criteria
            if (lib.nfct_get_attr_u32(ct, _ATTR_ORIG_IPV4_SRC) == m["src_ip"]
                    and lib.nfct_get_attr_u32(ct, _ATTR_ORIG_IPV4_DST) == m["dst_ip"]
                    and socket.ntohs(lib.nfct_get_attr_u16(ct, _ATTR_ORIG_PORT_DST)) == m["dst_port"]
                    and socket.ntohs(lib.nfct_get_attr_u16(ct, _ATTR_REPL_PORT_DST)) == m["repl_dport"]):
                self._result = socket.ntohs(
                    lib.nfct_get_attr_u16(ct, _ATTR_ORIG_PORT_SRC)
                )
                return _NFCT_CB_STOP
        except Exception:
            pass
        return _NFCT_CB_CONTINUE

    def original_src_port(
        self,
        client: tuple[str, int],
        orig_dst: tuple[str, int],
        protocol: int = IPPROTO_TCP,
    ) -> int | None:
        """Recover the pre-NAT source port for a transparently-proxied flow.

        Args:
            client: the accepted socket's peer address (peername) =
                (original source IP, possibly NAT-mangled source port).
            orig_dst: the original destination (SO_ORIGINAL_DST) =
                (dst IP, dst port).

        Returns:
            The original source port, or None if unavailable / not found.
        """
        if not self.available:
            return None
        # Use a fresh handle per query: a DUMP that doesn't fully drain would
        # leave stale data on a reused netlink socket and corrupt later queries.
        handle = None
        try:
            handle = self._lib.nfct_open(_CONNTRACK, 0)
            if not handle:
                return None
            # Enlarge the receive buffer so a full-table DUMP isn't truncated by
            # ENOBUFS; bound the recv so a lost reply can't hang the event loop.
            try:
                fd = self._lib.nfct_fd(handle)
                sock = socket.socket(fileno=fd)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
                sock.settimeout(1.0)
                sock.detach()  # the conntrack handle owns the fd
            except Exception:
                pass
            self._lib.nfct_callback_register(handle, _NFCT_T_ALL, self._cb, None)

            self._criteria = {
                "src_ip": ip_to_int(client[0]),
                "dst_ip": ip_to_int(orig_dst[0]),
                "dst_port": orig_dst[1],
                "repl_dport": client[1],
            }
            self._result = None
            family = ctypes.c_uint32(_AF_INET)
            self._lib.nfct_query(handle, _NFCT_Q_DUMP, ctypes.byref(family))
            return self._result
        except Exception:
            return None
        finally:
            self._criteria = None
            if handle:
                try:
                    self._lib.nfct_close(handle)
                except Exception:
                    pass

    def close(self):
        # Nothing persistent to release: handles are per-query.
        pass
