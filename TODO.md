# TODO

## Done

- [x] DNS PID tracking via kprobe/udp_sendmsg (cgroup hooks don't fire for loopback)
- [x] Add comprehensive tests to workflow for all combinations
- [x] DNS to external (e.g. 8.8.8.8) - added dns_to_pid map keyed by src_port only
- [x] Test unified_proxy.py with mitmproxy + netfilterqueue - working in CI
- [x] UDP non-DNS PID tracking via netfilterqueue + scapy (tested with port 9999)
- [x] Block direct proxy connections via iptables mangle+filter

## Next Steps

- [ ] Consider removing IPv6 code (untested, GitHub runners lack IPv6)

## Ideas

- [ ] Reject untracked connections in mitmproxy addon (defense in depth once PID tracking is reliable)
