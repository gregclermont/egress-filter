# Audit Checklist

Comprehensive list of areas to audit, organized by category.

## Security: Bypass Vectors

- [ ] **S1. Direct-to-proxy-port blocking only covers 127.0.0.1**
  `iptables.sh:31-32` — rules block direct connections to 8080/8053 on `127.0.0.1`, but not on `0.0.0.0`, `127.0.0.2`, or the host's real IP. A process could potentially connect to the proxy directly via an alternate address, bypassing transparent redirect behavior.

- [ ] **S2. Conntrack fast-path skips nfqueue for subsequent UDP packets in a flow**
  `iptables.sh:37,42-43` and `nfqueue.py:41-47` — after the first non-DNS UDP packet gets mark 4 saved to conntrack, all subsequent packets in the same 5-tuple skip nfqueue entirely. If the first packet passes policy but the flow changes character, later packets are never re-evaluated.

- [ ] **S3. Packet mark spoofing by userspace**
  `iptables.sh` — marks 1, 2, 4 are used for routing decisions. Can a process with sufficient capabilities set its own packet marks (e.g., via `SO_MARK`) to influence the iptables flow? Mark 2 would redirect traffic to the DNS port; mark 4 would establish a conntrack fast-path entry.

- [ ] **S4. Policy file TOCTOU between pre.js write and proxy.sh chown**
  `pre.js:89-90` writes `/tmp/egress-policy.txt` as the runner user. `proxy.sh:73-75` chowns it to root. Between these two operations, a concurrent process could modify the file. The window is small (the file is written before start is called) but exists.

- [ ] **S5. DNS cache poisoning via forged DNS responses**
  `mitmproxy.py:266-296` — `dns_response` records IP→hostname mappings from DNS answers. If an attacker controls a DNS server response for an allowed domain, they could bind arbitrary IPs to that hostname. Subsequent TCP/HTTPS connections to those IPs would then be allowed by hostname match via the DNS IP cache.

- [ ] **S6. Control socket authentication — empty GITHUB_ACTION_REPOSITORY**
  `control.py:84,98-109` — `EXPECTED_ACTION_REPO` is captured at module import time. If it's empty (env var unset), the verify_caller check requires the caller to also have an empty `GITHUB_ACTION_REPOSITORY` from trusted ancestry. The `get_trusted_github_env` pipeline (runner cgroup + Runner.Worker ancestry) should prevent this, but the empty-matches-empty case deserves explicit analysis.

- [ ] **S7. Sudoers backup readable in /tmp**
  `sudo.py:13,24-28` — the backup of `/etc/sudoers.d/runner` is written to `/tmp/sudoers-runner-backup` with default permissions. Any process can read it. The content itself is probably not sensitive (it's the standard runner sudoers config), but it's sloppy.

- [ ] **S8. mitmproxy CA key persists after proxy stops**
  `proxy.sh:136-139` — the CA cert is appended to the system cert store and copied to `/tmp`. After the proxy shuts down, the CA private key remains in `/root/.mitmproxy/`. If a later step runs as root (or sudo is re-enabled), it could extract the key and MITM connections using the still-trusted cert.

- [ ] **S9. Container process detection relies solely on cgroup string matching**
  `mitmproxy.py:92` checks for `docker-` in the cgroup path from `proc_dict`. `proc.py:166-171` — `is_container_process` also checks for `docker-` or `/docker/` in cgroup path. A process could manipulate its cgroup path (if it has permissions) or use a non-Docker container runtime that doesn't match these patterns. False negative → no TLS passthrough → connection failure. False positive → TLS passthrough → bypasses URL/path-level inspection.

- [ ] **S10. Raw socket blocking doesn't cover all bypass vectors**
  `conn_tracker.bpf.c:86-100` — blocks `AF_PACKET` and `SOCK_RAW`. What about `IPPROTO_RAW` with `SOCK_DGRAM`? What about `io_uring` or other kernel interfaces that could send packets without going through the socket syscall?

- [ ] **S11. iptables cleanup flushes entire tables**
  `iptables.sh:91-94` — cleanup flushes ALL rules in mangle, nat, and filter tables. This destroys any rules that Docker, other software, or the user's workflow may have added. Could break networking for containers or other services.

- [ ] **S12. Placeholder substitution is naive string replacement**
  `parser.py:757-762` — `{owner}` and `{repo}` are replaced via `str.replace`. If `GITHUB_REPOSITORY` contains characters meaningful to the policy grammar (unlikely for GitHub repo names, but worth verifying), it could inject or break policy rules.

- [ ] **S13. Wildcard hostname matching is multi-level**
  `matcher.py:70-157` — `*.example.com` matches `a.b.c.example.com`, not just `a.example.com`. This is intentional but could surprise policy authors who expect single-level matching like TLS certificates. A rule for `*.cdn.example.com` would match deeply nested subdomains.

## Security: PID Attribution

- [ ] **S14. BPF map LRU eviction under high connection rates**
  `conn_tracker.bpf.c:52-56` — the map holds 65536 entries. Under heavy connection load, entries are evicted by LRU. If an entry is evicted before the proxy looks it up, the connection gets no PID attribution. Connections without PID get empty proc info, so attribute-based rules (exe, cgroup, step) won't match — the connection is blocked (safe default). But it means legitimate traffic could be incorrectly blocked.

- [ ] **S15. PID recycling race**
  Between when BPF records `4-tuple → PID` and when the proxy reads `/proc/PID/*`, the process could exit and the PID could be reused by a different process. This would attribute the connection to the wrong process.

- [ ] **S16. DNS 4-tuple cache key is (src_port, txid) — 16-bit txid collision**
  `nfqueue.py:100-101` and `mitmproxy.py:205-206` — DNS transaction IDs are 16-bit. Under high DNS query rates from the same source port, collisions are plausible. A collision would cause wrong PID/IP attribution for the DNS query.

- [ ] **S17. BPF kprobe records dst_ip in network byte order, userspace uses ip_to_int with little-endian unpack**
  `utils.py:22-25` — `ip_to_int` uses `<I` (little-endian) to match how BPF stores `sin_addr.s_addr` on x86. This is correct for x86 but would break on big-endian architectures. The project only targets x86 GitHub runners, but it's an implicit assumption.

## Security: Process Identity

- [ ] **S18. Trusted GitHub env var extraction relies on process ancestry depth**
  `proc.py:135-168` and `gha.py:24-67` — `find_trusted_github_pids` walks process ancestry looking for `RUNNER_WORKER_EXE` at a specific path. `validate_runner_environment` checks exact indices (node24 at index 4, Runner.Worker at index 5). If GitHub changes the runner process tree (adds/removes a wrapper), this breaks entirely.

- [ ] **S19. Process ancestry uses /proc/PID/exe which can be deleted/replaced**
  `proc.py:13-18` — `read_exe` reads the `/proc/PID/exe` symlink. If the binary is deleted (common during updates), the symlink becomes `(deleted)`. If a process replaces its binary via `execve`, the exe changes. This could affect Runner.Worker detection.

- [ ] **S20. get_proc_info reads multiple /proc files non-atomically**
  `proc.py:184-209` — reads exe, cmdline, cgroup, and environ in separate syscalls. The process could change state between reads. For short-lived processes, some reads could fail while others succeed, producing inconsistent info.

## Robustness / Reliability

- [ ] **R1. Supervisor only restarts proxy once**
  `supervisor.sh:15,68-72,88-96` — `MAX_RESTARTS=1`. After a second crash, supervisor cleans up iptables and exits. This is the right call (prevents crash loops), but means a single transient failure (e.g., resource exhaustion) followed by a mitmproxy bug would leave the runner with no proxy. Need to verify this doesn't silently break the workflow.

- [ ] **R2. Proxy startup timeout is 10 seconds**
  `proxy.sh:104-115` and `supervisor.sh:46-58` — both wait up to 10 seconds for port 8080. Under heavy load or slow dependency loading, mitmproxy could take longer. The failure mode is the entire action failing.

- [ ] **R3. No connection log rotation or size limit**
  `logging.py:33,55-69` — `connections.jsonl` grows unbounded. A workflow with millions of connections (e.g., a CI job that runs many HTTP requests) could fill the disk partition.

- [ ] **R4. nfqueue buffer overflow under packet flood**
  `nfqueue.py:137-150` — the nfqueue is processed via asyncio `add_reader` callback. If packets arrive faster than they can be processed (e.g., mitmproxy is slow), the kernel nfqueue buffer fills up. Default behavior is to drop packets, which could break legitimate connections.

- [ ] **R5. dns_cache on BPFState is a plain dict with no size limit**
  `bpf.py:38` — `self.dns_cache = {}` grows unbounded. Every DNS query adds an entry (keyed by `(src_port, txid)`), and entries are only removed when consumed by `dns_request`. If `dns_request` never fires for some entries (e.g., packet dropped), entries leak.

- [ ] **R6. atexit handler and explicit cleanup can double-cleanup BPF**
  `main.py:139-143,244-246` — the `atexit` handler is unregistered in the `finally` block, but if `shutdown_tasks` raises before reaching `atexit.unregister`, the atexit handler runs during interpreter shutdown and calls `bpf.cleanup()` again. The cleanup does try/except per link, so it's probably safe, but double-cleanup of `bpf_obj.__exit__` could be problematic.

- [ ] **R7. asyncio.wait with FIRST_COMPLETED — unhandled task exceptions**
  `main.py:221-229` — when one task completes, the other tasks are still running. The `done` set is checked for exceptions, but if the stop_signal completes normally while a background task has an unhandled exception, it's only logged in `shutdown_tasks`. Verify no exceptions are silently swallowed.

- [ ] **R8. Control socket timeout handling**
  `control.py:170-175` — 5-second timeout for reading the command. If the client connects but sends nothing (or sends slowly), the handler blocks the asyncio event loop for up to 5 seconds. Multiple such connections could degrade proxy responsiveness.

- [ ] **R9. mitmproxy shutdown is synchronous in an async context**
  `main.py:58` — `master.shutdown()` is called in a `finally` block. If this blocks for a long time, it delays the entire shutdown sequence including iptables cleanup.

## Logic / Correctness

- [ ] **L1. Two different ip_to_int functions with different byte orders**
  `utils.py:12-25` uses little-endian (`<I`) for BPF map lookups. `matcher.py:51-53` uses big-endian (`!I`) for CIDR matching. Both are correct for their purposes, but having two functions with the same name doing different things is a maintenance hazard.

- [ ] **L2. Path rules silently dropped when no URL base in context**
  `parser.py:391-393` — if a path rule (`/foo/bar`) appears without a preceding URL-base header (`[https://example.com]`), it returns `None` and the rule is silently discarded. No warning is emitted.

- [ ] **L3. validate_policy doesn't catch rules silently dropped by visit_rule**
  `parser.py:871-898` — `validate_policy` only catches `ParseError`. Rules that parse successfully but are dropped by visitor logic (e.g., path rules without URL base, L2 above) are not reported as errors.

- [ ] **L4. Header context leaks between unrelated rule groups**
  `parser.py:815-838` — the PolicyVisitor preserves header context across lines. If a header sets attributes (e.g., `exe=curl`) and later rules don't explicitly reset via `[]`, those attributes persist and apply to subsequent rules. This is by design but could cause surprising behavior when rules from different sections interact.

- [ ] **L5. match_method defaults None method to GET**
  `matcher.py:231-246` — if an event has `method=None`, it's treated as GET. This affects non-HTTP connection types that match against URL rules. Should non-HTTP events ever reach method matching?

- [ ] **L6. DNS dual-check only looks at IP/CIDR rules for resolver**
  `matcher.py:551-586` — `_match_dns` checks the resolver is allowed by IP/CIDR rules with UDP protocol. A hostname rule for the DNS server (e.g., `dns.google`) wouldn't satisfy the resolver check, even if the IP matches via DNS cache.

- [ ] **L7. Policy defaults in audit mode: invalid policy lines cause sys.exit(1)**
  `main.py:197-203` — in enforcement mode, invalid policy lines cause exit. In audit mode, they're warned but skipped. However, the warning is a GitHub Actions annotation, not a log entry. If the warning is missed, the user won't know rules were silently dropped.

- [ ] **L8. Unquoted attribute values have wildcards active by default**
  `parser.py:707-708` and `types.py:11-15` — `AttrValue` defaults to `literal=False`. Unquoted values like `exe=/usr/bin/git` allow wildcard matching, meaning `*` in the value acts as a glob. Quoting (`exe="/usr/bin/git"`) makes it literal. Backtick (`` exe=`/usr/bin/g*t` ``) explicitly enables wildcards. The distinction between unquoted and backtick-quoted is that both allow wildcards, which makes backtick quoting pointless for that purpose.

- [ ] **L9. DNS response handler records IPs from AAAA records despite IPv6 being blocked**
  `mitmproxy.py:287-290` — AAAA records are processed and their IPs cached. Since IPv6 is blocked at the kernel level, these cache entries will never be looked up and just waste space.

## Architecture

- [ ] **A1. Entire proxy runs as root**
  The Python proxy (mitmproxy, scapy, netfilterqueue, parsimonious, and all their transitive dependencies) runs as root. Any RCE vulnerability in these libraries gives root access to the runner.

- [ ] **A2. No policy hot-reload**
  Policy is loaded once at startup. The only way to change policy is to restart the proxy (which means the supervisor uses up its one restart). There's no mechanism to reload policy at runtime.

- [ ] **A3. No health check or liveness probe**
  There's no way for the action or workflow to check if the proxy is still functioning correctly. If mitmproxy enters a degraded state (e.g., accepting connections but not forwarding them), traffic silently hangs.

- [ ] **A4. DNS 4-tuple coordination between nfqueue and mitmproxy is fragile**
  `bpf.py:38` — the `dns_cache` dict on BPFState is the rendezvous point between nfqueue (writes pre-NAT 4-tuple) and mitmproxy (reads via src_port+txid). This relies on nfqueue always processing the packet before mitmproxy sees the DNS request. If timing is off (e.g., nfqueue is slow), mitmproxy logs a cache miss and the DNS query loses PID attribution.

- [ ] **A5. Connection logging format is implicit**
  `logging.py:55-69` — `log_connection` takes `**kwargs` and writes whatever it gets. There's no schema or validation. Different callers pass different fields. The CLI analyzer (`cli.py`) must guess the format. A field rename in one handler silently breaks log analysis.

- [ ] **A6. Error handling in mitmproxy addon uses decorator that re-raises**
  `handlers/__init__.py:9-18` — `log_errors` catches exceptions, logs them, and re-raises. This means mitmproxy's error handling determines what happens next. If mitmproxy swallows the re-raised exception for some hook types, the connection proceeds unlogged.
