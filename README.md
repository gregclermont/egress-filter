# Egress Filter

Network egress control for GitHub Actions workflows. Uses eBPF for kernel-level connection tracking and a transparent proxy to attribute every outbound connection to the process that made it.

## The Problem

CI/CD pipelines routinely execute third-party code: actions, build tools, and dependencies. A compromised component can exfiltrate secrets, inject malware into build artifacts, or establish command-and-control channels—all from within a trusted workflow.

**Example attack scenario:**

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install        # Dependency executes postinstall script
                                # Script phones home to attacker.com with $GITHUB_TOKEN
      - run: npm run build
```

Without egress controls, this exfiltration succeeds silently. The workflow logs show a successful build.

**With Egress Filter:**

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: gregclermont/egress-filter@v1
        with:
          policy: |
            github.com action=actions/checkout
            *.npmjs.org

      - uses: actions/checkout@v4
      - run: npm install        # postinstall script tries to reach attacker.com
                                # Connection blocked, logged, build fails
      - run: npm run build
```

The connection to `attacker.com` is blocked because it's not in the allowlist. The connection log shows:

```json
{"type":"tcp","dst":"attacker.com:443","pid":4521,"exe":"/usr/bin/node","policy":"deny"}
```

## How It Works

The system operates at multiple layers to prevent bypass:

1. **eBPF connection tracking** — Kernel probes (`kprobe/tcp_connect`, `kprobe/udp_sendmsg`) record the PID for every outbound connection in a BPF hash map before the connection leaves the machine.

2. **Transparent proxy** — iptables redirects TCP traffic to mitmproxy (port 8080) and DNS to its DNS mode (port 8053). UDP packets pass through netfilter queue for DNS detection.

3. **PID lookup** — The proxy queries the BPF map to find which process initiated each connection, then walks `/proc` to extract the executable path, command line, cgroup, and GitHub Actions context (step, action repository).

4. **Policy enforcement** — Each connection is checked against the allowlist. Non-matching connections are blocked (or logged in audit mode).

### Bypass Prevention

- **IPv6 blocked at kernel level** — BPF cgroup hooks reject all IPv6 to force traffic through the IPv4 proxy
- **Raw sockets blocked** — BPF prevents `SOCK_RAW` and `AF_PACKET` to stop iptables bypass via crafted packets
- **Network namespace escape blocked** — `kernel.unprivileged_userns_clone=0` prevents creating new network namespaces
- **sudo disabled by default** — Prevents privileged escapes (flush iptables, create namespaces, etc.)

## Quick Start

Add the action as the first step in your job:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: gregclermont/egress-filter@v1
        with:
          policy: |
            # Package registry
            *.npmjs.org

            # GitHub (scoped to checkout action)
            github.com action=actions/checkout

      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test
```

### Developing a Policy

Start in audit mode to discover what your workflow needs:

```yaml
- uses: gregclermont/egress-filter@v1
  with:
    audit: true   # Log only, don't block
```

After the workflow runs, download the connection log artifact and analyze it against your policy:

```bash
gh run download <run-id> -n egress-connections
python -m proxy.policy .github/workflows/build.yml --analyze-log connections.jsonl
```

The CLI shows which connections would be blocked, with process context:

```
BLOCKED connections (would fail with this policy):
------------------------------------------------------------
  https://registry.npmjs.org  [exe=/usr/bin/node, step=build.__run_1]
  tcp://evil.com:443  [exe=/usr/bin/node]

Summary: 12 allowed, 2 blocked (out of 14 unique connections)
```

Add `-v` to also see allowed connections and which rule matched them. Add rules for legitimate blocked connections, then remove `audit: true` to enforce.

For quick inspection without the CLI, use jq:

```bash
jq -r 'select(.policy=="deny") | "\(.dst_ip):\(.dst_port) \(.exe)"' connections.jsonl | sort -u
```

## Policy Syntax

Policies use an allowlist model—connections not matching any rule are blocked. Each line specifies an allowed destination:

```yaml
policy: |
  # Hostname (port 443/tcp implied)
  api.github.com

  # Explicit port and protocol
  8.8.8.8:53/udp

  # CIDR range
  10.0.0.0/8:*

  # Wildcard subdomains
  *.amazonaws.com

  # Prefix wildcard
  derp*.tailscale.com

  # URL with path (GET/HEAD only by default)
  https://api.github.com/repos/*/releases

  # URL with method
  POST https://api.github.com/repos/*/issues

  # Placeholders for current repository (from GITHUB_REPOSITORY)
  https://github.com/{owner}/{repo}/*
```

### Process Scope Constraints

Rules can be restricted to specific processes:

| Constraint | Description | Example |
|------------|-------------|---------|
| `action=` | GitHub Action repository (JavaScript actions only) | `github.com action=actions/checkout` |
| `step=` | Job and step identifier | `example.com step=build.__run_2` |
| `exe=` | Executable path | `*.tailscale.com exe=/usr/bin/tailscaled` |
| `arg=` | Match any command line argument | `example.com arg=--config=/etc/app.conf` |
| `arg[N]=` | Match specific argument by index | `example.com arg[0]=node` |
| `cgroup=` | Linux cgroup path (or `@docker`, `@host`) | `168.63.129.16 cgroup=/azure.slice/*` |

Multiple constraints combine with AND logic—all must match.

See [docs/POLICY.md](docs/POLICY.md) for full syntax documentation.

### Built-in Defaults

GitHub Actions infrastructure is allowed automatically:

- `127.0.0.53:53/udp` — systemd-resolved (local DNS resolver)
- `168.63.129.16:80|32526 cgroup=...walinuxagent.service` — Azure wireserver (scoped to agent)
- `results-receiver.actions.githubusercontent.com` — Job result reporting

## Connection Log

All connections are logged to a JSONL file, uploaded as the `egress-connections` artifact by default.

```json
{"ts":"2024-01-15T10:30:45.123Z","type":"https","dst_ip":"104.16.23.35","dst_port":443,"url":"https://registry.npmjs.org/lodash","method":"GET","exe":"/usr/bin/node","cmdline":["node","/app/install.js"],"cgroup":"/actions_job/abc123","step":"build.__run_1","policy":"allow","src_port":54321,"pid":3847}
{"ts":"2024-01-15T10:30:46.456Z","type":"tcp","dst_ip":"93.184.216.34","dst_port":443,"exe":"/usr/bin/node","cmdline":["node","/tmp/malicious.js"],"cgroup":"/actions_job/abc123","policy":"deny","src_port":54322,"pid":3892}
```

Fields:

| Field | Description | Present |
|-------|-------------|---------|
| `ts` | Timestamp (ISO 8601) | Always |
| `type` | Protocol: `http`, `https`, `tcp`, `udp`, `dns` | Always |
| `dst_ip` | Destination IP address | Always |
| `dst_port` | Destination port | Always |
| `policy` | Policy match result: `allow`, `deny` | Always |
| `src_port` | Source port | Always |
| `pid` | Process ID | Always |
| `exe` | Executable path | When available |
| `cmdline` | Command line arguments (list) | When available |
| `cgroup` | Linux cgroup path | When available |
| `step` | GitHub step (`{job}.{action_id}`) | When available |
| `action` | GitHub Action repository | JavaScript actions only |
| `url` | Full URL | `http`, `https` |
| `method` | HTTP method | `http`, `https` |
| `host` | Hostname (SNI) | `https` passthrough |
| `name` | DNS query name | `dns` |

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `policy` | Egress policy rules (one per line) | (none) |
| `audit` | Log connections without blocking | `false` |
| `allow-sudo` | Keep sudo enabled for runner user | `false` |
| `upload-log` | Upload connection log as artifact | conditional |

### Connection Log Upload

By default, the connection log is only uploaded as an artifact when `audit: true` or when a connection was blocked. This reduces artifact noise for successful runs while ensuring logs are available for debugging. Set `upload-log: 'true'` to always upload, or `'false'` to never upload.

### sudo Behavior

By default, sudo is disabled because root access can bypass egress controls (e.g., flush iptables rules, create network namespaces, kill the proxy). Set `allow-sudo: true` if your workflow requires it.

For workflows that only need sudo temporarily (e.g., Tailscale setup), you can disable it after:

```yaml
- uses: gregclermont/egress-filter@v1
  with:
    allow-sudo: true

- uses: tailscale/github-action@v3  # Needs sudo for setup

- uses: gregclermont/egress-filter/disable-sudo@v1  # Lock down sudo

# Remaining steps run without sudo
```

The `enable-sudo` sub-action can re-enable it later if needed.

## Requirements

- **GitHub-hosted Ubuntu runners only** (`ubuntu-latest`, `ubuntu-24.04`)
- Self-hosted runners are not supported
- IPv6 is blocked (traffic forced through IPv4 proxy)

## Limitations

- **`action=` requires JavaScript actions** — Docker actions, composite actions, and `run:` steps don't have `GITHUB_ACTION_REPOSITORY` in their environment. Use `step=` or `exe=` instead.
- **Detached daemons lose GitHub context** — Background processes that daemonize lose their parent relationship to Runner.Worker. Use `exe=` to scope their traffic.
- **No WebSocket inspection** — WebSocket connections are logged but not inspected after the upgrade handshake.

## Acknowledgments

This project was inspired by:

- [step-security/harden-runner](https://github.com/step-security/harden-runner) — Pioneered egress filtering for GitHub Actions with MITM proxying
- [GitHubSecurityLab/actions-permissions](https://github.com/GitHubSecurityLab/actions-permissions) — Demonstrated using mitmproxy for GitHub Actions traffic analysis

## License

MIT
