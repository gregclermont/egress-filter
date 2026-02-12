# Writing Egress Filter Policies

This document explains how to write effective egress filter policies for GitHub Actions workflows.

## Policy Syntax

Each line in a policy specifies an allowed destination with optional scope constraints:

```
hostname_or_ip [port_spec] [scope...]
```

### Basic Examples

```yaml
policy: |
  # Allow all traffic to example.com (port 443/tcp by default)
  example.com

  # Allow specific port
  api.example.com:443

  # Allow IP range
  10.0.0.0/8

  # Allow UDP DNS
  8.8.8.8:53/udp

  # Multiple ports
  192.168.1.1:80|443

  # Any port
  10.0.0.0/8:*
```

### Wildcards

Wildcards are supported for hostnames:

```yaml
# Subdomain wildcards (match any depth of subdomains)
*.example.com         # Matches sub.example.com, a.b.example.com

# Label wildcards (fnmatch pattern on a single label)
derp*.tailscale.com   # Matches derp1.tailscale.com, derp99.tailscale.com
us-west-*.aws.com     # Matches us-west-1.aws.com, us-west-2.aws.com
d*rp.example.com      # Matches darp.example.com, d123rp.example.com

# Combined: subdomain wildcard + label wildcard
*.derp*.example.com   # Matches foo.derp1.example.com, a.b.derp99.example.com
```

Note: `*.example.com` requires at least one subdomain — it does not match `example.com` itself.

### URL Rules

Full URL rules allow matching on scheme, host, and path:

```yaml
# Path with wildcard segments (* matches one segment, trailing * matches any depth)
https://api.github.com/repos/*/releases
https://api.github.com/repos/myorg/*

# Wildcards in URL hostnames use the same hostname wildcard rules
https://productionresultssa*.blob.core.windows.net/*

# Method restriction (default: GET|HEAD for URL rules)
POST https://api.github.com/repos/*/issues
GET|POST https://example.com/api/*
```

URL hostnames support the same wildcard forms as hostname rules (`*.example.com`, `prefix*.example.com`, `*.prefix*.example.com`), with wildcards only in the first label.

### Headers

Headers (`[...]`) set context for subsequent rules. This avoids repeating the same base URL, port, or constraints:

```yaml
# URL base header — subsequent path rules are relative to it
[https://api.github.com]
/repos/*/releases
/repos/*/tags
POST /repos/*/issues

# Port/protocol header
[:53/udp]
8.8.8.8
8.8.4.4

# Method header
[GET|POST]
https://api.example.com/data
https://api.example.com/query

# Attribute header — applies constraints to all subsequent rules
[action=actions/checkout]
github.com
*.githubusercontent.com

# Reset to defaults (port 443/tcp, methods GET|HEAD, no attributes)
[]
```

### DNS-Only Rules

DNS-only rules allow resolving a domain without allowing egress connections to it. This is useful when a process needs to look up a domain but connect to its IPs via a separate IP/CIDR rule:

```yaml
dns:example.com
dns:*.internal.corp
```

### TLS Passthrough

The `passthrough` keyword skips TLS MITM interception for specific hostnames. Use this for services with certificate pinning, embedded trust stores, or sensitive traffic where you don't want the proxy to decrypt TLS:

```yaml
# Per-rule passthrough
pinned.example.com passthrough

# Passthrough with scope constraints
*.docker.io passthrough cgroup=@docker

# Passthrough with explicit port
registry.example.com:443 passthrough

# Header context for multiple passthrough rules
[passthrough]
pinned-service.example.com
another-pinned.example.com

# Passthrough header with attributes
[passthrough cgroup=@docker]
registry.example.com
auth.example.com

# Reset back to normal rules
[]
normal-host.com
```

**How it works:**

1. A connection must first match an allow rule (hostname, wildcard, IP, etc.)
2. Passthrough rules are evaluated as a separate phase — if the allowed connection also matches a passthrough rule, TLS interception is skipped
3. The connection is still logged (with `passthrough: true`) but the proxy does not decrypt it

**Restrictions:**

- Only `host` and `wildcard_host` rules support passthrough. IP, CIDR, URL, path, and DNS-only rules with `passthrough` are rejected at validation time and silently dropped at runtime.
- Passthrough only applies at the TLS stage (`tls_clienthello`). Since TLS is not decrypted, URL path matching and HTTP method filtering are not available for passthrough connections.
- A passthrough-only rule (without a matching allow rule) does not allow the connection — the connection must be allowed first.

### Placeholders

Policy text supports `{owner}` and `{repo}` placeholders, substituted from the `GITHUB_REPOSITORY` environment variable at runtime:

```yaml
https://github.com/{owner}/{repo}/*
```

When using the CLI for offline analysis, pass `--repo OWNER/REPO` to substitute these.

## Scope Constraints

Scope constraints restrict which processes can access a destination. Multiple constraints can be combined.

### `action=` - GitHub Action Repository

Restricts access to processes running within a specific GitHub Action:

```yaml
github.com action=actions/checkout
api.tailscale.com action=tailscale/github-action
```

**Important Limitation**: `action=` only works for **JavaScript/TypeScript actions** (using node). It does NOT work for:

- **Composite actions** - These run shell steps directly under Runner.Worker, and GitHub does not set `GITHUB_ACTION_REPOSITORY` in the shell environment
- **`run:` steps** - Inline shell scripts don't have `GITHUB_ACTION_REPOSITORY` set
- **Processes spawned as daemons** - Background processes that detach from the action's process tree lose the GitHub context

### `step=` - GitHub Actions Step

Restricts access to a specific step (job + action identifier):

```yaml
example.com step=build.__run_2
api.example.com step=deploy.__actions_checkout
```

The step format is `{GITHUB_JOB}.{GITHUB_ACTION}`. This works for both actions and `run:` steps, but the `GITHUB_ACTION` value for run steps is auto-generated (e.g., `__run_2`).

### `exe=` - Executable Path

Restricts access to processes with a specific executable:

```yaml
# Only tailscaled daemon can access these
controlplane.tailscale.com exe=/usr/bin/tailscaled
log.tailscale.com exe=/usr/bin/tailscaled
```

This is useful for:
- Daemon processes that run outside the GitHub Actions process tree
- System services
- Specific binaries regardless of how they were invoked

### `arg=` / `arg[N]=` - Command Line Arguments

Match against command line arguments:

```yaml
# Match any argument in the command line
example.com arg=--config=/etc/app.conf

# Match a specific argument by index (0-based)
example.com arg[0]=node
example.com arg[1]=server.js
```

### `image=` - Docker Container Image

Restricts access to processes running in a specific Docker container image. Supports wildcards:

```yaml
# Exact image match
registry.example.com image=python:3.12-alpine

# Wildcard tag
registry.example.com image=node:*

# Wildcard with registry prefix
*.github.com image=ghcr.io/myorg/*
```

This works for both `docker run` containers and `docker://` action steps. The image name is resolved by querying the Docker daemon's API via its Unix socket, so it reflects the image name as Docker sees it.

### `cgroup=` - Control Group

Restricts access by Linux cgroup path. Supports wildcards and shortcuts:

```yaml
# Exact cgroup path
168.63.129.16 cgroup=/azure.slice/walinuxagent.service

# Wildcard match
10.0.0.0/8:* cgroup=/system.slice/*

# Shortcut: match Docker container processes
registry.example.com cgroup=@docker

# Shortcut: match host processes (not in containers)
api.example.com cgroup=@host
```

## Best Practices

### 1. Prefer Scoped Rules

Always try to scope rules to reduce attack surface:

```yaml
# Good - scoped to specific action
github.com action=actions/checkout

# Avoid - allows any process
github.com
```

### 2. Use `exe=` for Daemons

Background daemons lose GitHub context. Use `exe=` to scope their traffic:

```yaml
# tailscaled runs as a daemon, not under the action's process tree
*.tailscale.com exe=/usr/bin/tailscaled
```

### 3. Combine Scopes for Defense in Depth

```yaml
# Most restrictive - both action and exe must match
pkgs.tailscale.com action=tailscale/github-action exe=/home/runner/.../node
```

### 4. Document Your Policies

Use comments to explain why each rule exists:

```yaml
policy: |
  # actions/checkout needs GitHub API access
  github.com action=actions/checkout

  # npm registry for dependency installation
  registry.npmjs.org step=build.__run_1
```

## Understanding Process Ancestry

The egress filter tracks which process made each network request by:

1. Using eBPF to capture the PID making the connection
2. Walking the process tree to find Runner.Worker
3. Reading environment variables from the direct child of Runner.Worker

This means:
- For **node actions**: The node process is the direct child, and has `GITHUB_ACTION_REPOSITORY` set
- For **composite actions**: A bash shell is the direct child, and only has `GITHUB_ACTION` set
- For **detached daemons**: The process tree doesn't lead back to Runner.Worker, so no GitHub context is available

## Example: Tailscale Action

Here's a complete policy for `tailscale/github-action@v4`:

```yaml
policy: |
  # v4 is a node action - downloads and API calls have action= context
  pkgs.tailscale.com action=tailscale/github-action
  api.tailscale.com action=tailscale/github-action

  # tailscaled daemon runs detached - use exe= instead
  controlplane.tailscale.com exe=/usr/bin/tailscaled
  log.tailscale.com exe=/usr/bin/tailscaled
  *.tailscale.com exe=/usr/bin/tailscaled
```

Note: v3 was a composite action and would require `exe=/usr/bin/curl` instead of `action=`.

## Debugging Policies

### Iterating on a Policy

The recommended workflow for developing a policy:

1. **Run your workflow in audit mode** (logs connections but doesn't block):
   ```yaml
   - uses: gregclermont/egress-filter@v1
     with:
       audit: true
   ```

2. **Download the connection log** (uploaded automatically as an artifact):
   ```bash
   gh run download -n egress-connections <run-id>
   ```

3. **Analyze against your policy**:
   ```bash
   egress-filter analyze --log connections.jsonl workflow.yml
   ```

4. **Iterate** - add rules for blocked connections, re-run analysis until all pass.

5. **Remove `audit: true`** to enable enforcement.

### Connection Log Format

Each entry in `connections.jsonl` includes:
- `type`: Connection type (`http`, `https`, `tcp`, `udp`, `dns`)
- `exe`: Executable path
- `cmdline`: Full command line
- `cgroup`: Linux cgroup path
- `step`: GitHub step identifier (if available)
- `action`: GitHub action repository (if available)
- `image`: Docker container image (if available)
- `policy`: Whether it was allowed or denied

### Installing the CLI

The policy CLI can be installed standalone without the heavy proxy dependencies (mitmproxy, etc.):

```bash
# Run directly without installing (recommended for one-off use)
uvx --from 'git+https://github.com/gregclermont/egress-filter' egress-filter validate workflow.yml

# Install as a global tool
uv tool install 'git+https://github.com/gregclermont/egress-filter'
egress-filter validate workflow.yml

# Or with pip
pip install 'git+https://github.com/gregclermont/egress-filter'
```

### CLI Options

```bash
# Validate policy syntax
egress-filter validate workflow.yml

# Analyze connections against policy (verbose shows allowed connections too)
egress-filter analyze --log connections.jsonl -v workflow.yml

# Dump parsed rules as JSON
egress-filter validate workflow.yml --dump-rules

# Analyze GitHub API permissions from connection log
egress-filter permissions connections.jsonl
```

### Enable Debug Logging

The proxy reads `VERBOSE` from its environment, but it's not passed through the `sudo env` wrapper by default. To enable verbose logging, the env var must be added to the `sudoEnv` array in `src/action/pre.js`. This is mainly useful for development — proxy logs are written to `/tmp/proxy.log` and mitmproxy logs to `/tmp/mitmproxy.log`.
