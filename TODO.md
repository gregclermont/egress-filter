# TODO

## Done

- [x] DNS PID tracking via kprobe/udp_sendmsg (cgroup hooks don't fire for loopback)
- [x] Add comprehensive tests to workflow for all combinations
- [x] DNS to external (e.g. 8.8.8.8) - added dns_to_pid map keyed by src_port only
- [x] Test unified_proxy.py with mitmproxy + netfilterqueue - working in CI
- [x] ALL non-DNS UDP PID tracking via netfilterqueue + scapy (excludes DNS, loopback, root)
- [x] Block direct proxy connections via iptables mangle+filter
- [x] Add IPv6 blocker BPF (blocks ALL IPv6 including IPv4-mapped to prevent proxy bypass)
- [x] Hybrid DNS 4-tuple tracking: nfqueue (mangle) captures original dst before NAT, mitmproxy looks up via (src_port, txid)
- [x] DNS detection by packet structure (haslayer(DNS)) not just port 53 - catches DNS on non-standard ports

## Ideas

- [ ] Reject untracked connections in mitmproxy addon (defense in depth once PID tracking is reliable)
