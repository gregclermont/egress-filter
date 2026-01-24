# UDP Fast-Path via Conntrack Marks

This document explains how the egress filter implements a fast-path for UDP packets to reduce nfqueue overhead.

## Problem

All UDP packets go through nfqueue for DNS detection and PID tracking. This works but adds latency and CPU overhead for every packet, even when subsequent packets to the same destination don't need re-processing.

## Solution

Use conntrack marks to skip nfqueue for packets belonging to already-processed connections:

1. First packet of a connection goes through nfqueue
2. nfqueue handler sets a packet mark
3. Packet reinjects and iptables saves the mark to conntrack
4. Subsequent packets match connmark and skip nfqueue entirely

## Packet Flow

```
First packet (mark=0, connmark=0):
    ↓
    connmark match 0x4/0x4? → NO
    ↓
    mark match 0x2? → NO
    ↓
    mark match 0x4/0x4? → NO
    ↓
    exclusions (systemd-resolve, proxy cgroup)
    ↓
    NFQUEUE → Python handler
                  ↓
              DNS packet?
               /      \
             yes       no
              ↓         ↓
          mark=2    mark=4
          (redirect) (fastpath)
              \       /
               ↓     ↓
            pkt.repeat()
                  ↓
    Packet reinjects at chain start
                  ↓
    connmark match 0x4/0x4? → NO
                  ↓
    mark match 0x2? ─────────────────→ YES (DNS) → RETURN → nat REDIRECT :8053
                  ↓ NO
    mark match 0x4/0x4? → YES (non-DNS)
                  ↓
    CONNMARK --save-mark
                  ↓
    RETURN

Subsequent non-DNS packets (mark=0, connmark=4):
    ↓
    connmark match 0x4/0x4? → YES
    ↓
    RETURN (fast-path: skip nfqueue)

Subsequent DNS packets (mark=0, connmark=0):
    ↓
    connmark match 0x4/0x4? → NO (DNS has no connmark)
    ↓
    Goes through NFQUEUE again (every DNS query is logged)
```

## Mark Bits

| Bit | Value | Meaning |
|-----|-------|---------|
| 1 (0x2) | 2 | DNS redirect to port 8053 |
| 2 (0x4) | 4 | Fast-path (save to conntrack) |

Marks used:
- `mark=2`: DNS UDP, redirect only (no fast-path - every query logged)
- `mark=4`: Non-DNS UDP, fast-path only

DNS intentionally does NOT get fast-path to ensure every query is proxied and logged.
This prevents a bypass where only the first DNS query would go through the proxy.

## Key Implementation Details

### Why `repeat()` Instead of `accept()`

The Python netfilterqueue library provides two relevant verdicts:

- **`accept()`**: Permits the packet but may skip remaining iptables rules
- **`repeat()`**: Reinjects the packet at the start of the chain, preserving mark changes

With `accept()`, the CONNMARK save rule was never hit (0 packet matches in CI). The packet was being accepted but not continuing through subsequent rules.

With `repeat()`, the packet:
1. Gets marked in Python
2. Reinjects at chain start with mark preserved
3. Matches the mark-based rules (CONNMARK save + RETURN)
4. Avoids re-queuing because the mark check happens before NFQUEUE

### Rule Ordering

The iptables rules must be ordered carefully:

```bash
# 1. Fast-path: skip if connmark already set (subsequent packets)
-m connmark --mark 4/4 -j RETURN

# 2. Handle packets just processed by nfqueue (marked, being repeated)
-m mark --mark 4/4 -j CONNMARK --save-mark
-m mark --mark 4/4 -j RETURN

# 3. Exclusions
-m owner --uid-owner systemd-resolve -j RETURN
-m cgroup --path "$proxy_cgroup" -j RETURN

# 4. Queue remaining packets
-j NFQUEUE --queue-num 1
```

The mark-based rules (step 2) must come BEFORE NFQUEUE to catch repeated packets.

## Performance

From CI logs with fast-path enabled:

| Rule | Packets |
|------|---------|
| connmark RETURN (fast-path) | 50 |
| CONNMARK save | 35 |
| NFQUEUE | 41 |

Interpretation:
- 41 unique UDP connections went through nfqueue
- 35 got marked (6 were DNS with redirect mark)
- 50 packets total hit the fast-path (subsequent packets of same connections)

## Files

- `src/setup/iptables.sh`: Rule definitions with connmark fast-path
- `src/proxy/handlers/nfqueue.py`: Packet handling with mark and repeat verdict

## References

- [python-netfilterqueue](https://github.com/oremanj/python-netfilterqueue) - Documents `repeat()` verdict: "Restarts processing from the beginning of the netfilter hook, preserving any payload or mark changes"
- [Using Nfqueue with Python the right way](https://byt3bl33d3r.github.io/using-nfqueue-with-python-the-right-way.html) - Discusses mark visibility patterns
- [Using NFQUEUE and libnetfilter_queue](https://home.regit.org/netfilter-en/using-nfqueue-and-libnetfilter_queue/) - Low-level nfqueue documentation
