# TODO

## Done

- [x] DNS PID tracking via kprobe/udp_sendmsg (cgroup hooks don't fire for loopback)
- [x] Add comprehensive tests to workflow for all combinations
- [x] DNS to external (e.g. 8.8.8.8) - added dns_to_pid map keyed by src_port only
- [x] Test unified_proxy.py with mitmproxy + netfilterqueue - working in CI

## Next Steps

- [ ] HTTP via direct proxy - loopback connection to proxy, no BPF hook fires
- [ ] Consider removing IPv6 code (untested, GitHub runners lack IPv6)
- [ ] Add iptables rules to redirect non-DNS UDP to netfilterqueue for logging
