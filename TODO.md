# TODO

## Done

- [x] DNS PID tracking via kprobe/udp_sendmsg (cgroup hooks don't fire for loopback)
- [x] Add comprehensive tests to workflow for all combinations
- [x] DNS to external (e.g. 8.8.8.8) - added dns_to_pid map keyed by src_port only
- [x] Test unified_proxy.py with mitmproxy + netfilterqueue - working in CI
- [x] UDP non-DNS PID tracking via netfilterqueue + scapy (tested with port 9999)
- [x] Block direct proxy connections via iptables mangle+filter
- [x] Add IPv6 blocker BPF (blocks native IPv6, allows IPv4-mapped addresses)

## Known Limitations

- IPv4-mapped IPv6 (::ffff:x.x.x.x) bypasses mitmproxy transparent mode - this is an iptables REDIRECT limitation with AF_INET6 sockets, not a BPF tracking issue. These connections still succeed but aren't proxied.

## Ideas

- [ ] Reject untracked connections in mitmproxy addon (defense in depth once PID tracking is reliable)
