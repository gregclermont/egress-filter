# TODO

## High Priority

- [x] Convert connection log to JSONL, ensure only one event logged per connection
- [x] Collect process executable path and command line
- [ ] Tighten and organize code for readability

## Medium Priority

- [ ] Collect GitHub job step info from process env for the log
- [ ] Investigate UDP fast path using eBPF TC to mark allowed packets based on 4-tuple and skip nfqueue

## Low Priority

- [ ] Review main.py: remove unused/unnecessary code, reorder for readability, consider splitting into multiple files
- [ ] setup/proxy.sh: consider combining the two waiting loops (port 8080 and CA certificate) into one
- [ ] Check if we need both UDP BPF handlers; add comment explaining why we track loopback for UDP; investigate if needed for TCP
- [ ] Consider moving package.json / package-lock.json to src/action/
- [ ] Consider moving python package management files to src/proxy/
- [ ] Disable sudo (backup /etc/sudoers.d/runner, make it empty, restore at end)
- [ ] Disable docker/containers (disable sudo to prevent reinstall, uninstall docker, nuke files, break socket perms)

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
