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

We use BPF hooks attached to the root cgroup (`/sys/fs/cgroup`), which catches all processes system-wide including containers:

**TCP**: `cgroup/connect4` hook
```c
SEC("cgroup/connect4")
int cgroup_connect4(struct bpf_sock_addr *ctx) {
    // Fires at connect() time, src_port already assigned for TCP
    // Records (dst_ip, src_port, dst_port) → PID
}
```

**UDP**: `kprobe/udp_sendmsg` hook
```c
SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx) {
    // Fires when sending UDP, captures 4-tuple and PID
}
```

**Why root cgroup works for containers**: When attached to the root cgroup, BPF hooks fire for all processes in the cgroup hierarchy, including Docker containers which run under `/sys/fs/cgroup/system.slice/docker-*.scope`.

**Why kprobe for UDP**: At UDP `connect()` time, the socket isn't bound yet—`src_port` is 0. The kprobe fires after the port is assigned.

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

## Implementation Details

### Files

- `src/bpf/conn_tracker.bpf.c`: `cgroup/connect4` for TCP, `kprobe/udp_sendmsg` for UDP
- `src/proxy/bpf.py`: Attaches BPF programs to root cgroup and kprobes
- `src/setup/iptables.sh`: PREROUTING rules for docker0 interface
- `tests/connection_tests/`: Python test framework with Docker tests

## Limitations

1. **Container process metadata**: While we capture the correct PID, the `step` field won't be populated for container processes since they don't inherit GitHub Actions environment variables.

2. **Docker's internal DNS**: Containers use Docker's embedded DNS at 127.0.0.11 by default. When the container queries this, Docker forwards to the actual resolver. We intercept this forwarded query, which means we see the correct destination but attribute it to the process inside the container (via kprobe), not Docker's daemon.
