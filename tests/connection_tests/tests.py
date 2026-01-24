"""Test definitions for connection tracking tests.

Each test has:
  - marker: Unique ID for matching in logs (greppable)
  - type: Connection type (http, https, dns, udp, tcp)
  - target: Connection target
  - expect_logged: Whether we expect it to appear in the connection log
  - description: Human-readable description
"""

# Tests that run on the host (or in docker host mode)
HOST_TESTS = [
    # HTTP/HTTPS
    ("H001", "http", "http://example.com/", True, "HTTP to external"),
    ("H002", "https", "https://example.com/", True, "HTTPS to external"),

    # DNS
    ("H003", "dns", "example.com", True, "DNS via system resolver"),

    # UDP (unconnected: sendto with dest in msg_name)
    ("H004", "udp", "8.8.8.8:9999", True, "UDP to external"),

    # TCP (non-HTTP)
    ("H005", "tcp", "github.com:22", True, "TCP to external (SSH port)"),

    # UDP connected (connect + send, dest in socket not msg_name)
    ("H006", "udp_connected", "8.8.8.8:9998", True, "UDP connected socket"),

    # IPv6 blocking (should NOT be logged - blocked by BPF cgroup hooks)
    ("H007", "tcp6", "2606:4700:4700::1111:80", False, "TCP IPv6 blocked"),
]

# Tests that run in docker bridge mode
BRIDGE_TESTS = [
    ("B001", "http", "http://example.com/", True, "HTTP from bridge container"),
    ("B002", "https", "https://example.com/", True, "HTTPS from bridge container"),
    ("B003", "dns", "example.com", True, "DNS from bridge container"),
    ("B004", "udp", "8.8.8.8:9999", True, "UDP from bridge container"),
    ("B005", "tcp", "github.com:22", True, "TCP from bridge container"),
]

# Tests that run in docker host mode
# These share the host network, so behavior should match HOST_TESTS
HOSTMODE_TESTS = [
    ("D001", "http", "http://example.com/", True, "HTTP from host-mode container"),
    ("D002", "https", "https://example.com/", True, "HTTPS from host-mode container"),
    ("D003", "dns", "example.com", True, "DNS from host-mode container"),
    ("D004", "udp", "8.8.8.8:9999", True, "UDP from host-mode container"),
    ("D005", "tcp", "github.com:22", True, "TCP from host-mode container"),
]
