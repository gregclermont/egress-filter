# TODO

## High Priority

- [x] Convert connection log to JSONL, ensure only one event logged per connection
- [x] Collect process executable path and command line
- [x] Tighten and organize code for readability

## Medium Priority

- [x] Collect GitHub job step info from process env for the log
- [x] Investigate UDP fast path using eBPF TC to mark allowed packets based on 4-tuple and skip nfqueue
  - Implemented using conntrack marks instead of eBPF TC (simpler)
  - nfqueue sets packet mark, uses repeat() verdict to reinject at chain start
  - CONNMARK save rule catches repeated packets, saves mark to conntrack
  - Subsequent packets match connmark and skip nfqueue (fast-path confirmed working)

## Low Priority

- [x] Review main.py: remove unused/unnecessary code, reorder for readability, consider splitting into multiple files
- [x] Check if we need both UDP BPF handlers; add comment explaining why we track loopback for UDP; investigate if needed for TCP
- [ ] Consider moving package.json / package-lock.json to src/action/
- [ ] Consider moving python package management files to src/proxy/
- [ ] Disable sudo (backup /etc/sudoers.d/runner, make it empty, restore at end)
- [ ] Disable docker/containers (disable sudo to prevent reinstall, uninstall docker, nuke files, break socket perms)
- [x] Test how the proxy handles traffic from docker containers
  - Bridge mode (default): bypasses proxy (container's network namespace)
  - Bridge mode + DNAT: traffic proxied + PID tracked via kprobe + SO_ORIGINAL_DST
  - Host mode: traffic proxied + PID tracked via kprobe
  - PID tracking works for bridge+DNAT and host mode (kprobe/tcp_connect is kernel-wide)

## Done

- [x] Structure as a reusable GitHub Action (node) with pre/post hooks
- [x] DNS PID tracking via kprobe/udp_sendmsg (cgroup hooks don't fire for loopback)
- [x] Add comprehensive tests to workflow for all combinations
- [x] DNS to external (e.g. 8.8.8.8) - added dns_to_pid map keyed by src_port only
- [x] Test unified_proxy.py with mitmproxy + netfilterqueue - working in CI
- [x] ALL non-DNS UDP PID tracking via netfilterqueue + scapy (excludes DNS, loopback, root)
- [x] Block direct proxy connections via iptables mangle+filter (TCP 8080 + UDP 8053)
- [x] Add IPv6 blocker BPF (blocks ALL IPv6 including IPv4-mapped to prevent proxy bypass)
- [x] Hybrid DNS 4-tuple tracking: nfqueue (mangle) captures original dst before NAT, mitmproxy looks up via (src_port, txid)
- [x] DNS detection by packet structure (haslayer(DNS)) not just port 53 - catches DNS on non-standard ports

## Ideas

- [ ] Reject untracked connections in mitmproxy addon (defense in depth once PID tracking is reliable)
