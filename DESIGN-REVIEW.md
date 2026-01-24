# Design Review: Implementation vs Design Doc

This document compares the original design (`gha-egress-firewall-design.md`) with the current implementation, identifies gaps, and tracks resolutions.

## Divergences from Design Doc

### 1. BPF Map Structure

| Design Doc | Actual Implementation |
|------------|----------------------|
| Key: `(src_ip, src_port, dst_ip, dst_port)` | Key: `(dst_ip, src_port, dst_port, protocol)` - no src_ip |
| Value: `ConnInfo` struct with pid, ppid, comm, cgroup_id, timestamp | Value: just `u32` PID |
| Single map for connections | Single map, process info fetched from `/proc` at log time |

**Resolution:** Keep current approach. No src_ip needed (transparent proxy sees localhost). Fetching process info from /proc at log time works well in practice.

**Known limitation:** Very short-lived processes (especially unconnected UDP) may exit before proxy reads /proc, resulting in incomplete process info (PID only). Mitigated in tests with sleep(0.2). Unlikely to be an issue in real-world CI workloads where processes are longer-lived. Revisit if needed.

---

### 2. DNS Handling

| Design Doc | Actual Implementation |
|------------|----------------------|
| DNS on port 53 | DNS on port 8053 |
| DNS cache: IP → domain with TTL | DNS cache: `(src_port, txid)` → `(pid, dst_ip, dst_port)` for PID correlation only |
| Cache used for IP→domain validation | Cache used only for hybrid DNS tracking (nfqueue captures pre-NAT dest) |

**Resolution:** Port 8053 is intentional to avoid conflict with systemd-resolved on port 53. Current `dns_cache` stays for PID correlation. Will add separate IP → domain cache (with TTL) for allowlist validation when implementing Phase 1.

---

### 3. UDP Handling

| Design Doc | Actual Implementation |
|------------|----------------------|
| eBPF cgroup hooks (`cgroup/sendmsg4`) for filtering | netfilterqueue + scapy for interception |
| Complex rule system (process, ip, domain, port) | No rules - logging only |
| `exe_path_hash` for secure process matching | No exe hash - direct `/proc` lookup |
| `dns_allowed_ips` map for domain-based rules | Not implemented |

**Resolution:** Keep nfqueue + Python approach. Having all packets pass through Python handler makes feature development (logging, filtering, blocking) easier and more coherent. Fast-path via conntrack marks addresses performance for non-DNS UDP. Will add filtering logic (drop instead of accept) when implementing UDP rules.

---

### 4. IPv6 Strategy

| Design Doc | Actual Implementation |
|------------|----------------------|
| IPv6 support mentioned for UDP rules | All IPv6 blocked via `cgroup/connect6` and `cgroup/sendmsg6` |
| No explicit blocking strategy | Forces all traffic through IPv4 proxy |

**Resolution:** IPv6 is not supported on GitHub-hosted Ubuntu runners (the primary target). Blocking IPv6 completely is intentional for simplicity. No plans to add IPv6 proxying.

---

### 5. Proxy Exclusion

| Design Doc | Actual Implementation |
|------------|----------------------|
| Dedicated `mitmproxy` user | systemd-run scope (`egress-filter-proxy.scope`) |
| iptables excludes by UID | iptables excludes by cgroup path (better for root processes) |

**Resolution:** Intentional improvement. Cgroup-based exclusion works for root processes (UID-based wouldn't). Properly handles Docker `--network=host` containers running as root. systemd-run provides clean lifecycle management.

---

### 6. Hook Points

| Design Doc | Actual Implementation |
|------------|----------------------|
| `kprobe/tcp_connect` + `kprobe/tcp_close` | `kprobe/tcp_connect` only (no close tracking) |
| `client_connected` for eBPF lookup | `tls_clienthello`, `request`, `tcp_start`, `dns_request` |

**Resolution:** Intentional simplifications. LRU map (65536 entries) handles cleanup via auto-eviction, no need for tcp_close. Protocol-specific hooks allow protocol-aware logging. May revisit if limitations arise with new features or real-world use cases.

---

### 7. Container Support

| Design Doc | Actual Implementation |
|------------|----------------------|
| Not addressed | Explicit support: bridge mode (PREROUTING), host mode, TLS passthrough for containers |

**Resolution:** Developed through experimentation. Ideally would monitor containers as perfectly as host. Current approach:
- Bridge mode: PREROUTING rules on docker0
- Host mode: Works via kprobe (kernel-wide)
- TLS: Passthrough only (SNI-based logging/validation) - cannot inject mitmproxy CA into containers

**Known limitation:** No TLS interception for containers. Can validate domain via SNI but cannot inspect HTTP headers, URL paths, or POST bodies inside HTTPS from containers.

---

## TODO: Completing the Vision

### Phase 1: Domain Allowlisting (Core Security)

**Design principle:** Always require an allowlist config (even minimal like `policy: allow-all` or `policy: block-all`). Logs always show decision (allow/block) regardless of mode. Enforcement is toggleable.

- [ ] **Policy modes**
  - `mode: monitor` - log decisions but don't enforce (default for rollout)
  - `mode: enforce` - actually block disallowed traffic

- [ ] **Enhanced logging**
  - All events include: `action: allow|block`, `enforced: true|false`
  - Add: `reason`, `sni`, `host_header` where applicable
  - Existing fields: ts, type, dst_ip, dst_port, exe, cmdline, cgroup, step, src_port, pid

- [ ] **DNS Cache with TTL** - Map IP → domain with expiration
  - Min TTL floor (60s), max ceiling (3600s)
  - LRU eviction at 10,000 entries

- [ ] **Allowlist class** - Domain matching with wildcards
  - Wildcard semantics TBD (see Q10 - needs research)
  - Case-insensitive, trailing dot handling

- [ ] **Validation in mitmproxy hooks**
  - `dns_request`: Block disallowed domains (return REFUSED)
  - `tls_clienthello`: Validate IP + SNI before handshake
  - `request`: Validate IP + Host + domain match (anti-domain-fronting)
  - `tcp_start`: Validate IP in cache from allowed domain (handling TBD, see Q12)

- [ ] **Block action** - Reset (TCP RST) or 403 response

- [ ] **GitHub Action interface**
  - Inputs: `mode`, `allowed-domains`, `allowed-domains-file`, `block-action`, `log-file`
  - Outputs: `blocked-count`, `log-file` path

### Phase 2: URL Filtering

**Scope:** HTTP/HTTPS only. Non-HTTP TCP filtered by domain/port/process, not URL paths.

- [ ] **URLRule class** - Pattern matching with globs
  - `host/path` format with `*` and `**` support
  - Optional method filtering
  - Path normalization (prevent bypasses)

- [ ] **URLFilter** - Rule evaluation
  - Block rules first, then allow rules
  - `default-url-policy`: allow or block

- [ ] **Logging** - Include matched rule, reason in events

- [ ] **Action interface** - Add `url-blocked-count` output

**Note:** URL filtering not available for container HTTPS (TLS passthrough - SNI only).

### Phase 3: UDP Filtering

**Approach:** All filtering in Python using nfqueue. Uses 4-tuple, PID (from BPF), and userspace-collected process metadata (/proc). No BPF-side filtering needed.

- [ ] **UDP rule system**
  - Match by: domain, ip CIDR, port, process (exe path)
  - Rules can combine multiple criteria (AND logic)
  - Uses existing DNS cache for domain → IP resolution

- [ ] **Filtering in nfqueue handler**
  - Check rules against packet + process info
  - Drop packet (instead of accept) if not allowed
  - DNS packets: always allow through to mitmproxy for logging

- [ ] **Action interface**
  - Input: `allowed-udp` - UDP rules (inline or file)
  - Output: `udp-blocked-count`

**Note:** If Python-based approach hits performance/reliability blockers, explore alternatives (eBPF cgroup hooks).

### Phase 4: Additional CA Trust (as needed)

- [ ] **CA trust for more tools** - Add as user demand arises
  - Java keystore
  - Docker daemon config
  - Ruby/OpenSSL

### Phase 5: Security Hardening

**Note:** May prioritize this research before Phase 1 - understanding bypass vectors informs the security model.

#### Implemented hardening

- [ ] **Disable sudo** (default: disabled)
  - sudo allows complete firewall bypass (`sudo iptables -F`)
  - Backup sudoers, make empty, restore at end
  - Input: `allow-sudo: true` to opt-out for workflows that need it

- [ ] **Disable docker/containers** (optional)
  - Containers are a bypass vector (SNI-only validation)
  - Disable sudo first (prevents reinstall), uninstall docker, nuke files
  - Input: `allow-containers: false` to enable this hardening

- [ ] **Reject untracked connections**
  - Defense in depth once PID tracking proven reliable
  - Separate toggle from monitor/enforce mode

#### Research completed

- [ ] **Block raw sockets (SOCK_RAW)** - FEASIBLE via capsh
  - **Finding:** CAP_NET_RAW is available on GHA runners - all raw socket types work
  - **Risk:** AF_PACKET sockets completely bypass iptables (can craft packets at Ethernet layer)
  - **Solution:** `capsh --drop=cap_net_raw` successfully blocks raw sockets
  - **Verified:** Normal network operations (curl, etc.) still work without CAP_NET_RAW
  - **Implementation:** Wrap user commands with capsh, or use systemd CapabilityBoundingSet
  - See: `experiments/raw_socket_bypass/` for test scripts

- [x] **eBPF LSM hooks** - NOT AVAILABLE on GHA runners
  - **Finding:** BPF not in active LSMs: `lockdown,capability,landlock,yama,apparmor,ima,evm`
  - **Alternative:** cgroup BPF hooks (cgroup/sock_create) ARE available

- [x] **Seccomp filtering** - AVAILABLE
  - **Finding:** seccomp available with actions: `kill_process kill_thread trap errno user_notif trace log allow`
  - Can be used to block specific syscalls (socket with SOCK_RAW, unshare with CLONE_NEWNET)

#### Still to investigate

- [ ] **Block network namespace creation**
  - `unshare(CLONE_NEWNET)` creates netns where iptables rules don't apply
  - Options: seccomp to block `unshare`/`clone` with CLONE_NEWNET
  - Ties into "disable containers" (Docker uses netns)

- [ ] **cgroup/sock_create hook** for raw socket blocking
  - Alternative to capsh approach
  - Can filter by socket type, family, protocol at kernel level
  - Already have cgroup BPF infrastructure in place

### Phase 6: Convenience Features

- [ ] **Presets** - Architecture TBD
  - At minimum: one built-in preset for Actions infrastructure (enabled by default)
    - `pipelines.actions.githubusercontent.com`, `results-receiver.actions.githubusercontent.com`, etc.
    - Required for GHA to function
  - Future: github-strict, npm-strict, pypi-strict
  - Open question: separate files vs built into action code

---

## Questions & Clarifications

### Q1: netfilterqueue vs eBPF cgroup for UDP filtering

Current impl uses nfqueue for UDP interception. Design doc uses eBPF cgroup hooks. Which approach going forward?

**Resolution:** _TBD_

---

### Q2: Why no src_ip in BPF map key?

Design doc includes it, implementation doesn't. Intentional? (Transparent proxy always sees connections from localhost?)

**Resolution:** _TBD_

---

### Q3: Why no tcp_close hook?

Design doc mentions `kprobe/tcp_close` for cleanup. Implementation uses LRU map instead. Sufficient?

**Resolution:** _TBD_

---

### Q4: DNS cache purpose shift

Design: IP → domain mapping for validation. Implementation: src_port+txid → (pid, dst_ip, dst_port) for PID correlation. Will both caches coexist?

**Resolution:** _TBD_

---

### Q5: DNS port 8053 vs 53

Why not use port 53 directly as in design doc? To avoid conflicting with systemd-resolved?

**Resolution:** _TBD_

---

### Q6: Is blanket IPv6 blocking permanent?

Current approach forces IPv4. Design doc implies IPv6 support. Long-term plan?

**Resolution:** _TBD_

---

### Q7: TLS passthrough for containers

Current impl skips MITM for container processes (no CA access). How will allowlist validation work? Only SNI-based?

**Resolution:** Two modes planned:
1. **Containers allowed:** SNI-based validation (best effort) - can block by domain, cannot do URL filtering or detect domain fronting
2. **Containers blocked:** Prevent creation/use at system level for stricter security (already on TODO list)

Real-world workloads may require containers, so provide best-effort controls. For workflows that don't need containers, treat them as a bypass mechanism to be blocked.

---

### Q8: exe_path_hash race condition

Design doc mentions ~100ms race window for new processes. Acceptable mitigation?

**Resolution:** Fail closed when not in monitor mode, once tracking reliability is proven. If PID resolution fails, connection is blocked. Escape hatch: allowlisting by IP+port (for all processes) bypasses PID requirement - failed PID resolution wouldn't block in that case.

---

### Q9: Domain-based UDP rule TTL

Honor DNS TTL or keep for job duration?

**Resolution:** Keep for job duration (option 2). DNS-resolved IPs for UDP rules don't expire during the CI job. Simplifies implementation and avoids breaking connections mid-job due to TTL expiry.

---

### Q10: Wildcard semantics confirmed?

`example.com` → allows `example.com` AND `*.example.com`
`*.example.com` → allows only subdomains

**Resolution:** OPEN. Needs research before deciding:
- Survey what other popular tools do (e.g., firewall tools, proxy allowlists, CSP, CORS)
- Consider concrete examples and edge cases
- Decide before implementing Phase 1 allowlisting

---

### Q11: Default UDP policy?

Block all except DNS? Block all except DNS + NTP?

**Resolution:** In filtering mode, everything blocked unless explicitly allowed by config. Default deny for all traffic including UDP. Users must allowlist DNS, NTP, etc. as needed.

---

### Q12: Non-HTTP TCP handling?

Allow if IP in DNS cache from allowed domain? Or block all non-HTTP TCP?

**Resolution:** OPEN. Needs real-world examples and threat modeling before deciding. Options include:
1. Allow if IP in DNS cache from allowed domain
2. Block all non-HTTP TCP
3. Require explicit port allowlisting (e.g., `github.com:22`)

---

### Q13: Process info storage

Design doc stores ppid, comm, cgroup_id in BPF map. Implementation fetches from /proc at log time. Change needed?

**Resolution:** See Divergence 1. Current approach works. Known limitation for very short-lived processes documented there.

---

### Q14: Reject untracked connections

When is PID tracking considered "reliable enough"? Criteria for enabling?

**Resolution:** OPEN. Needs real-world usage data first. Criteria for "reliable enough" to be defined after observing PID tracking in production workflows.

---
