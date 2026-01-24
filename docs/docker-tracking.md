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
# TCP: DNAT all TCP to proxy
iptables -t nat -A PREROUTING -i docker0 -p tcp -j DNAT --to ${DOCKER0_IP}:8080

# UDP: nfqueue for PID tracking, then DNAT DNS to proxy
iptables -t mangle -A PREROUTING -i docker0 -p udp -j NFQUEUE --queue-num 1
iptables -t nat -A PREROUTING -i docker0 -p udp -m mark --mark 2 -j DNAT --to ${DOCKER0_IP}:8053
```

This intercepts all TCP and UDP traffic from containers.

### Host Mode

Host mode containers share the host's network namespace. Traffic goes through the host's iptables rules, so our existing REDIRECT rules catch it automatically.

```bash
docker run --network host ...
```

No additional configuration needed.

## PID Tracking

### The Challenge

Initially, PID tracking failed for container traffic because:

1. **cgroup-scoped hooks**: The `sockops` BPF hook only fires for processes in the attached cgroup. Container processes run in Docker's cgroup hierarchy, not the runner's cgroup.

2. **Timing**: Hooking `tcp_v4_connect` is too early - the ephemeral source port isn't assigned yet.

### The Solution

We use `kprobe/tcp_connect` instead of `sockops`:

```c
SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    // ... capture 4-tuple and PID
}
```

**Why this works**:

1. **Kernel-wide**: kprobes fire for all processes system-wide, regardless of cgroup
2. **Correct timing**: `tcp_connect` is called after `tcp_v4_connect` assigns the source port
3. **Host PIDs**: `bpf_get_current_pid_tgid()` returns the PID from the host's namespace, not the container's

### Recovering Original Destination (DNAT)

For bridge+DNAT traffic, the packet's destination is rewritten to the proxy. We recover the original destination using `SO_ORIGINAL_DST`:

```
Container connects to → example.com:80
DNAT rewrites to      → proxy:8080
SO_ORIGINAL_DST       → example.com:80 (from conntrack)
```

mitmproxy automatically uses `SO_ORIGINAL_DST` in transparent mode, so `flow.server_conn.address` contains the original destination.

### 4-Tuple Matching

The key insight is that the 4-tuple matches across the interception:

| Component | kprobe captures | Proxy sees |
|-----------|----------------|------------|
| dst_ip | example.com | example.com (via SO_ORIGINAL_DST) |
| dst_port | 80 | 80 (via SO_ORIGINAL_DST) |
| src_port | 54321 | 54321 (preserved through DNAT) |

Since all components match, the BPF map lookup succeeds.

## Current Support Matrix

### TCP (HTTP/HTTPS)

| Mode | Proxied | PID Tracked | Notes |
|------|---------|-------------|-------|
| Bridge | Yes | Yes | DNAT in PREROUTING intercepts all TCP |
| Host | Yes | Yes | Works automatically via REDIRECT |

### UDP (DNS and other)

| Mode | Proxied | PID Tracked | Notes |
|------|---------|-------------|-------|
| Bridge | Yes | Yes | nfqueue in PREROUTING + DNAT to proxy |
| Host | Yes | Yes | Works automatically via existing rules |

All bridge mode traffic is now intercepted via PREROUTING rules added automatically by `iptables.sh`.

## Implementation Details

### Files Modified

- `src/bpf/conn_tracker.bpf.c`: Added `kprobe/tcp_connect` handler
- `src/proxy/bpf.py`: Attach kprobe to `tcp_connect`
- `tests/test_pid_tracking.sh`: Docker-specific test functions

### Test Functions

The test script includes specialized functions for docker tests:

- `run_docker_test`: Checks for connections from container IP (172.17.x.x) with a PID
- `run_docker_host_test`: Checks for connections without `step` field (containers lack GitHub env vars)

## Limitations

1. **Container process metadata**: While we capture the correct PID, the `step` field won't be populated for container processes since they don't inherit GitHub Actions environment variables.

2. **Docker's internal DNS**: Containers use Docker's embedded DNS at 127.0.0.11 by default. When the container queries this, Docker forwards to the actual resolver. We intercept this forwarded query, which means we see the correct destination but attribute it to the process inside the container (via kprobe), not Docker's daemon.
