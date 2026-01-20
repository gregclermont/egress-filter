# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Session Start

At the start of each session, read and display the contents of `TODO.md` to remind the user of pending tasks.

## Project Overview

eBPF-based connection-to-PID tracker integrated with mitmproxy transparent proxy. Attributes every network connection to the process that made it.

## Key Files

- `proxy.py` - mitmproxy addon with BPF-based PID tracking
- `src/bpf/port_tracker.bpf.c` - BPF program for connection tracking
- `.github/workflows/test-mitmproxy-wireguard.yml` - CI workflow

## How It Works

1. BPF program attaches to cgroup and tracks TCP connections via `sockops` hook
2. When a connection is made, BPF records `(dst_ip, src_port, dst_port)` → PID in an LRU hash map
3. mitmproxy in transparent mode intercepts traffic via iptables REDIRECT
4. proxy.py looks up the PID from BPF maps for each connection and logs it

## Running the Workflow

The workflow runs on `workflow_dispatch` (manual trigger):

```bash
gh workflow run test-mitmproxy-wireguard.yml
```

## Local Development

```bash
# Install dependencies
uv sync

# Compile BPF (requires Docker)
uv run tinybpf docker-compile src/bpf/port_tracker.bpf.c

# Run proxy (requires root for BPF)
sudo .venv/bin/python proxy.py
```

## BPF Map Structure

```python
class ConnKeyV4(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
    ]
```

## Dependencies

- tinybpf (from git) - BPF loading and map access
- mitmproxy - transparent proxy

See `pyproject.toml` for full dependency list.
