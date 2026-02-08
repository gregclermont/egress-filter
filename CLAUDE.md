# CLAUDE.md

## Session Start

Check GitHub Issues for pending tasks: `gh issue list`

## Workflow

- Work in **feature branches** with an associated PR; create the PR early (draft if needed) and push updates as you go
- Suggest GitHub Issues for TODOs/tangents rather than inline comments
- If the user gets sidetracked on a feature branch, gently suggest creating an issue for the tangent

## Project Overview

GitHub Action that acts as an egress firewall for GitHub-hosted Ubuntu runners. Intercepts all outbound network traffic via iptables + mitmproxy, attributes each connection to a PID via eBPF, and enforces an allow-list policy. Supports HTTP/HTTPS (with TLS MITM), raw TCP, DNS, and UDP.

## File Structure

```
action.yml               # GitHub Action definition (node24 runtime)
disable-sudo/            # Sub-action: disable sudo via control socket
enable-sudo/             # Sub-action: re-enable sudo via control socket
src/
├── action/              # Action JS hooks
│   ├── pre.js           # Install deps, write policy, start proxy
│   ├── main.js          # No-op status message
│   └── post.js          # Authenticated shutdown, iptables cleanup, upload logs
├── bpf/
│   └── conn_tracker.bpf.c  # BPF: kprobes for PID tracking, cgroup hooks for IPv6/raw socket blocking
├── runc_wrapper.py      # Standalone runc wrapper: injects mitmproxy CA cert into container rootfs
├── proxy/               # Python proxy package
│   ├── main.py          # Async orchestration: BPF setup, policy load, mitmproxy + nfqueue tasks
│   ├── bpf.py           # BPF loading (tinybpf), PID lookup, dns_cache dict for nfqueue→mitmproxy handoff
│   ├── control.py       # Unix socket server: authenticated shutdown/sudo commands via SO_PEERCRED
│   ├── sudo.py          # Disable/enable sudo by truncating /etc/sudoers.d/runner
│   ├── logging.py       # Operational log + JSONL connection event log
│   ├── proc.py          # /proc readers: exe, cmdline, cgroup, environ, ancestry, trusted GitHub env, Docker image lookup
│   ├── utils.py         # ip_to_int (little-endian for BPF), protocol constants
│   ├── purl.py          # Registry URL → PURL parser (npm, PyPI, Cargo)
│   ├── socket_dev.py    # Socket.dev API client: package security checks, caching, fail-open
│   ├── handlers/
│   │   ├── mitmproxy.py # Addon: TLS/HTTP/TCP/DNS hooks, policy enforcement, Socket.dev
│   │   └── nfqueue.py   # UDP: DNS detection → mark for redirect, non-DNS → policy check + fast-path
│   └── policy/
│       ├── types.py     # Rule, AttrValue, DefaultContext, HeaderContext
│       ├── parser.py    # PEG grammar (parsimonious), visitor → flat Rule list, placeholder substitution
│       ├── matcher.py   # ConnectionEvent matching: hostname/wildcard/URL/CIDR/IP, DNS dual-check
│       ├── enforcer.py  # PolicyEnforcer: check_http/https/tcp/dns/udp, audit mode, DNS IP cache
│       ├── dns_cache.py # IP→hostname cache (TTL-based, thread-safe, bounded)
│       ├── defaults.py  # Default rules (local DNS, Azure wireserver, GHA results receiver)
│       ├── gha.py       # Runner constants (cgroup, exe paths), environment validation
│       └── cli.py       # CLI: validate policy from workflow YAML, analyze connection logs
└── setup/
    ├── proxy.sh         # Lifecycle: install-deps, start (systemd scope + supervisor), stop
    ├── supervisor.sh    # Wraps proxy with restart-once-on-crash, lives in systemd scope
    ├── iptables.sh      # All iptables rules: TCP redirect, UDP nfqueue/DNS, Docker bridge, anti-bypass
    ├── deps.sha256      # Dependency manifest with SHA256 hashes
    └── generate-deps.py # Script to regenerate deps.sha256
tools/
    └── dump_mitmproxy_flows.py  # Dev tool: dump flow object structure for test mock creation
tests/                   # Policy unit tests (pytest + hypothesis)
```

## How It Works

1. **BPF kprobes** on `tcp_connect`/`udp_sendmsg` record `(dst_ip, src_port, dst_port, proto) → PID` in an LRU hash map (65536 entries)
2. **BPF cgroup hooks** block IPv6 (`connect6`/`sendmsg6`) and raw/packet sockets (`sock_create`) to prevent proxy bypass
3. **iptables** redirects TCP → mitmproxy :8080, sends UDP through nfqueue for DNS detection
4. **nfqueue** (mangle, pre-NAT): DNS packets get mark 2 → NAT redirects to mitmproxy :8053; non-DNS UDP gets policy-checked, allowed packets get mark 4 → conntrack fast-path
5. **mitmproxy** handles HTTP/HTTPS/TCP/DNS: looks up PID from BPF map, enforces policy, logs to JSONL. DNS responses populate an IP→hostname cache for later TCP correlation.
6. **Control socket** (`/tmp/egress-filter-control.sock`) authenticates callers via `SO_PEERCRED` + process ancestry + `GITHUB_ACTION_REPOSITORY` match. Used by post.js for shutdown.
7. **Startup hardening**: sudo disabled (sudoers truncated), user namespaces blocked (`unprivileged_userns_clone=0`), proxy runs in systemd scope for cgroup isolation
8. **Container TLS MITM**: `runc_wrapper.py` intercepts `runc create/run` to inject the mitmproxy CA cert into container rootfs (copies cert, appends to system CA bundles, injects env vars like `NODE_EXTRA_CA_CERTS`). Installed by `proxy.sh` as `/usr/bin/runc` (original moved to `runc.real`). Fails open on injection errors. Warns when pre-set env vars are skipped.
8. **Socket.dev integration** (opt-in via `socket-security: true`): After policy allows an HTTP request, `purl.py` checks if the URL is a package registry download (npm, PyPI, Cargo) and converts it to a PURL. `socket_dev.py` queries the Socket.dev API and blocks packages with critical/high severity alerts. Fail-open on API errors. Results cached in-memory.

## Running Tests

```bash
# Policy unit tests (the main local test suite)
uv run --with pytest --with hypothesis python -m pytest tests/

# Handler tests (require proxy dependencies)
uv run --extra proxy --with pytest python -m pytest tests/test_handler_mitmproxy.py tests/test_handler_nfqueue.py -v

# Integration tests run as GitHub Actions workflows (.github/workflows/test-*.yml)
# Trigger by pushing to the test branch:
git push -f origin HEAD:test
```

## Local Development

```bash
uv sync
uv run tinybpf docker-compile src/bpf/conn_tracker.bpf.c -o dist/bpf/conn_tracker.bpf.o  # requires Docker
sudo PYTHONPATH=src .venv/bin/python -m proxy.main  # requires root for BPF
```

### Dumping mitmproxy flow objects

`tools/dump_mitmproxy_flows.py` runs mitmproxy as an explicit proxy (no root needed) and dumps the flow object attributes that `MitmproxyAddon` accesses. Useful for creating realistic mock objects for handler tests.

```bash
# Terminal 1: start the dumper
uv run --extra proxy python tools/dump_mitmproxy_flows.py

# Terminal 2: generate flows
curl -x http://localhost:8080 http://example.com           # HTTP
curl -x http://localhost:8080 -k https://example.com       # HTTPS (MITM)
dig @127.0.0.1 -p 8053 example.com                        # DNS
```

Output is JSON with the attribute values and types for each hook (`tls_clienthello`, `request`, `tcp_start`, `dns_request`, `dns_response`, `tls_failed_client`).

## Policy DSL

Rules are parsed line-by-line with a PEG grammar. Headers (`[...]`) set context (port, protocol, methods, URL base, attributes) for subsequent rules. `[]` resets context. Secure defaults: port 443, TCP, methods GET|HEAD.

Rule types: hostname (`github.com`), wildcard (`*.github.com`), IP (`1.2.3.4`), CIDR (`10.0.0.0/8`), URL (`https://github.com/owner/repo/*`), path (`/api/*` under a URL-base header), DNS-only (`dns:example.com`).

Attributes: `exe=`, `cgroup=`, `step=`, `action=`, `image=`, `arg=`, `arg[N]=`. Port: `:443`, `:80|443`, `:*`. Protocol: `/tcp`, `/udp`. Methods: `GET|POST`.

The `for_runner` factory prepends infrastructure defaults and injects `cgroup=/system.slice/hosted-compute-agent.service` on all rules.

## Supported Runners

GitHub-hosted Ubuntu 24.04 x64 only. Platform enforced in `pre.js` (checks `ImageOS=ubuntu24`, `RUNNER_ENVIRONMENT=github-hosted`). The `.deb` packages in `src/setup/deps.sha256` are hardcoded to Ubuntu 24.04 amd64.

## Dependencies

Runtime (proxy): tinybpf (custom index), mitmproxy, netfilterqueue, scapy, parsimonious, pyyaml. See `pyproject.toml`.
