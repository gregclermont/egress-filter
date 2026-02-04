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
  # Allow all traffic to example.com
  example.com

  # Allow specific port
  api.example.com[:443]

  # Allow IP range
  10.0.0.0/8

  # Allow UDP DNS
  8.8.8.8[:53/udp]
```

### Wildcards

Wildcards are supported for hostnames:

```yaml
# Suffix wildcards (match any subdomain)
*.example.com      # Matches sub.example.com, a.b.example.com

# Prefix wildcards (match hostname prefix)
derp*.tailscale.com   # Matches derp1.tailscale.com, derp99.tailscale.com
us-west-*.aws.com     # Matches us-west-1.aws.com, us-west-2.aws.com
```

Note: Only one wildcard per hostname is allowed, and it must be at the start or end of a label.

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

### `cgroup=` - Control Group

Restricts access by Linux cgroup path:

```yaml
# Azure agent infrastructure
168.63.129.16 cgroup=/azure.slice/walinuxagent.service
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
   gh run download <run-id> -n egress-connections
   ```

3. **Analyze against your policy**:
   ```bash
   egress-policy workflow.yml --analyze-log connections.jsonl
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
- `policy`: Whether it was allowed or denied

### Installing the CLI

The policy CLI can be installed standalone without the heavy proxy dependencies (mitmproxy, etc.):

```bash
# Run directly without installing (recommended for one-off use)
uvx --from 'git+https://github.com/gregclermont/egress-filter' egress-policy workflow.yml

# Install as a global tool
uv tool install 'git+https://github.com/gregclermont/egress-filter'
egress-policy workflow.yml

# Or with pip
pip install 'git+https://github.com/gregclermont/egress-filter'
```

### CLI Options

```bash
# Validate policy syntax
egress-policy workflow.yml

# Analyze connections against policy (verbose shows allowed connections too)
egress-policy workflow.yml --analyze-log connections.jsonl -v

# Dump parsed rules as JSON
egress-policy workflow.yml --dump-rules
```

### Enable Debug Logging

Set `VERBOSE=1` in your workflow to see detailed proxy logs:

```yaml
env:
  VERBOSE: 1
```
