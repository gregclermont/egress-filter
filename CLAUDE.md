# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

eBPF-based connection-to-PID tracker for egress firewall. Maps network connections to the process that owns them, enabling mitmproxy to attribute connections to processes.

## Build Commands

Compile BPF programs (requires Docker or Lima with docker):
```bash
docker run --rm -v "$(pwd)":/src ghcr.io/gregclermont/tinybpf-compile src/bpf/port_tracker.bpf.c src/bpf/ipv6_blocker.bpf.c
```

Or using tinybpf CLI (once installed):
```bash
tinybpf docker-compile src/bpf/*.bpf.c
```

## Architecture

### BPF Programs

**port_tracker.bpf.c** - Connection tracking (always allows, just records):
- `handle_sockops` (SEC "sockops") - TCP connect tracking via sock_ops
- `handle_sendmsg4` (SEC "cgroup/sendmsg4") - UDP IPv4 tracking
- `handle_sendmsg6` (SEC "cgroup/sendmsg6") - UDP IPv6 tracking

**ipv6_blocker.bpf.c** - Optional IPv6 blocking (separate concern):
- `block_connect6` (SEC "cgroup/connect6") - TCP IPv6 blocking
- `block_sendmsg6` (SEC "cgroup/sendmsg6") - UDP IPv6 blocking
- Controlled by `config[0]`: set to 1 to block native IPv6

### Maps

**conn_to_pid_v4** (LRU_HASH, 65K entries):
- Key: `{dst_ip, src_port, dst_port, protocol}` (12 bytes, packed)
- Value: `{pid}` (4 bytes)

**conn_to_pid_v6** (LRU_HASH, 16K entries):
- Key: `{dst_ip[4], src_port, dst_port, protocol}` (24 bytes, packed)
- Value: same as v4

**config** (ARRAY, 1 entry) - in ipv6_blocker only:
- `config[0] = 1` enables IPv6 blocking

### Key Design Decisions

1. **No src_ip in keys** - source IP may be 0 for unbound sockets; src_port is sufficient for disambiguation
2. **No cleanup logic** - relies on LRU eviction to avoid race conditions with packet processing
3. **IPv4-mapped IPv6 addresses** (::ffff:x.x.x.x) are stored in the v4 map
4. **Separate blocker program** - can be loaded independently, attachment order determines whether blocked connections are tracked

## Dependencies

tinybpf is installed from git (github.com/gregclermont/tinybpf). To pick up changes:

```bash
uv sync --refresh
```

For local development with a local tinybpf checkout, temporarily change pyproject.toml:
```toml
dependencies = ["tinybpf @ file:///Users/user/src/tinybpf"]
```

## Running

The tracker requires root privileges for BPF operations. Use `tinybpf run-elevated` to run with sudo while preserving the venv:

```bash
# Install dependencies
uv sync

# Run the tracker (monitors all connections)
uv run tinybpf run-elevated main.py run

# Look up a specific connection
uv run tinybpf run-elevated main.py lookup 142.250.80.46 54321 443 --protocol tcp
```

## tinybpf API Reference

```python
import ctypes
import tinybpf

with tinybpf.load("port_tracker.bpf.o") as obj:
    # Attach to cgroup
    obj.program("handle_sockops").attach_cgroup("/sys/fs/cgroup")
    obj.program("handle_sendmsg4").attach_cgroup("/sys/fs/cgroup")
    obj.program("handle_sendmsg6").attach_cgroup("/sys/fs/cgroup")

    # Typed map access
    map_v4 = obj.maps["conn_to_pid_v4"].typed(key=ConnKeyV4, value=ctypes.c_uint32)
    for key, pid in map_v4.items():
        print(f"{key.src_port} -> {key.dst_ip}:{key.dst_port} = PID {pid}")
```

See https://raw.githubusercontent.com/gregclermont/tinybpf/main/llms.txt for full API.

## ctypes Structs (must match BPF exactly)

```python
import ctypes

class ConnKeyV4(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
    ]

class ConnKeyV6(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("dst_ip", ctypes.c_uint32 * 4),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
    ]

# Map value is just ctypes.c_uint32 (the PID)
```
