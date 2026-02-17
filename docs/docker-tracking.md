# Docker Container Traffic Tracking

This document explains how the egress filter tracks network traffic from Docker containers.

## Docker Networking Modes

Docker containers can use different networking modes, each with different implications for traffic interception:

| Mode | Network Namespace | iptables Apply? | Traffic Path |
|------|------------------|-----------------|--------------|
| Bridge (default) | Separate | No (container NS) | Container → docker0 → NAT → Internet |
| Host | Shared with host | Yes | Container → Host stack → Internet |

## Traffic Interception by Mode

### Bridge Mode

Bridge mode containers have their own network namespace. Traffic going to external destinations passes through the docker0 bridge interface, where we intercept it using PREROUTING rules.

**Automatic setup** (in `iptables.sh`):
```bash
# TCP: redirect to proxy
iptables -t nat -A PREROUTING -i docker0 -p tcp -j REDIRECT --to-port 8080

# UDP: nfqueue for PID tracking, then redirect DNS to proxy
iptables -t mangle -A PREROUTING -i docker0 -p udp -j NFQUEUE --queue-num 1
iptables -t nat -A PREROUTING -i docker0 -p udp -m mark --mark 2/2 -j REDIRECT --to-port 8053
```

This intercepts all TCP and UDP traffic from containers.

### Host Mode

Host mode containers share the host's network namespace. Traffic goes through the host's iptables rules, so our existing REDIRECT rules catch it automatically.

```bash
docker run --network host ...
```

No additional configuration needed.

## PID Tracking

### How It Works

We use kprobes which are kernel-wide and catch all processes regardless of network namespace:

**TCP**: `kprobe/tcp_connect` hook
```c
SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx) {
    // Fires at connect() time, captures 4-tuple and PID
    // Kernel-wide: works for host, host-mode, AND bridge containers
}
```

**UDP**: `kprobe/udp_sendmsg` hook
```c
SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx) {
    // Fires when sending UDP, captures 4-tuple and PID
}
```

**Why kprobe instead of cgroup hooks**: Cgroup hooks (`cgroup/connect4`) do fire for all processes including containers (cgroups are orthogonal to network namespaces), but at `connect()` time the source port hasn't been assigned yet (`src_port=0`). Since we need the source port for the 4-tuple key, we can't use cgroup hooks for TCP tracking. The `kprobe/tcp_connect` fires later in the connection sequence, after the kernel has assigned the ephemeral port.

### Recovering Original Destination

For bridge mode traffic, iptables REDIRECT rewrites the destination to localhost. mitmproxy recovers the original destination using `SO_ORIGINAL_DST` (from conntrack):

```
Container connects to → example.com:80
REDIRECT rewrites to  → localhost:8080
SO_ORIGINAL_DST       → example.com:80 (from conntrack)
```

### 4-Tuple Matching

The key insight is that the 4-tuple matches across the interception:

| Component | BPF captures | Proxy sees |
|-----------|-------------|------------|
| dst_ip | example.com | example.com (via SO_ORIGINAL_DST) |
| dst_port | 80 | 80 (via SO_ORIGINAL_DST) |
| src_port | 54321 | 54321 (preserved through REDIRECT) |

Since all components match, the BPF map lookup succeeds.

## Current Support Matrix

### TCP (HTTP/HTTPS)

| Mode | Proxied | PID Tracked | Notes |
|------|---------|-------------|-------|
| Bridge | Yes | Yes | REDIRECT in PREROUTING intercepts all TCP |
| Host | Yes | Yes | Works automatically via OUTPUT REDIRECT |

### UDP (DNS and other)

| Mode | Proxied | PID Tracked | Notes |
|------|---------|-------------|-------|
| Bridge | Yes | Yes | nfqueue in PREROUTING + REDIRECT to proxy |
| Host | Yes | Yes | Works automatically via existing rules |

## TLS MITM for Containers

Container HTTPS traffic is fully MITM'd, enabling URL/path matching, method filtering, and Socket.dev package scanning. This is achieved by injecting the mitmproxy CA certificate into containers at creation time using OCI bind mounts.

`src/runc_wrapper.py` intercepts `runc create/run` by replacing `/usr/bin/runc` (original moved to `runc.real`). On each container creation it:

1. Bind-mounts the CA cert read-only into `/tmp/mitmproxy-ca-cert.pem` in the container
2. For each system CA bundle found in the container (Debian, RHEL, Alpine paths), creates a merged copy (original + CA cert) on the host and bind-mounts it over the in-container path
3. Injects env vars into the OCI config (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `AWS_CA_BUNDLE`, `HEX_CACERTS_PATH`)

The wrapper uses bind mounts rather than direct rootfs modifications, so injected certs never appear in container image layers. This makes it safe for `docker build` contexts — even if a legacy (non-BuildKit) build triggers the host's runc, no CA artifacts end up in the built image.

The wrapper fails open: if injection fails, runc still runs normally. If a container image pre-sets CA-related env vars, the wrapper does not override them but logs a warning with the image name (queried from Docker API).

To disable container cert injection entirely (e.g., when the runc wrapper conflicts with a container runtime), set `container-certs: false`:

```yaml
- uses: gregclermont/egress-filter@v1
  with:
    container-certs: false
```

For containers that reject the proxy CA (certificate pinning, embedded trust stores), use the `passthrough` keyword to skip TLS interception:

```yaml
# Skip MITM for pinned containers
*.docker.io passthrough cgroup=@docker
```

## Implementation Details

### Files

- `src/bpf/conn_tracker.bpf.c`: `kprobe/tcp_connect` for TCP, `kprobe/udp_sendmsg` for UDP, cgroup hooks for IPv6 blocking
- `src/proxy/bpf.py`: Attaches BPF programs to kprobes and root cgroup
- `src/setup/iptables.sh`: PREROUTING rules for docker0
- `src/runc_wrapper.py`: Wraps runc to inject CA cert into containers via bind mounts
- `tests/connection_tests/`: Python test framework with Docker tests

## IPv6 Blocking

IPv6 must be blocked to force traffic through the IPv4 transparent proxy.

**All processes** (host, host-mode containers, and bridge containers) are blocked by BPF cgroup hooks (`cgroup/connect6`, `cgroup/sendmsg6`). Cgroups are orthogonal to network namespaces, so these hooks fire for all processes regardless of their network namespace.

Applications receive `EPERM` (Operation not permitted) when attempting IPv6 connections.

## Limitations

1. **Container process metadata**: While we capture the correct PID, the `step` field won't be populated for container processes since they don't inherit GitHub Actions environment variables.

2. **Docker's internal DNS**: Containers use Docker's embedded DNS at 127.0.0.11 by default. When the container queries this, Docker forwards to the actual resolver. We intercept this forwarded query, which means we see the correct destination but attribute it to the process inside the container (via kprobe), not Docker's daemon.

3. **CA injection is best-effort**: Runtimes that don't use the system CA store or the injected env vars (e.g., Java without keytool import, certificate pinning) will see TLS failures. Containers that pre-set CA-related env vars won't have them overridden. Use `passthrough` to skip MITM for affected hosts.
