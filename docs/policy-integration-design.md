# Policy Integration Design

Design document for integrating the policy matching engine into the proxy handlers.

## Current Architecture

```
                    ┌─────────────────────────────────────────┐
                    │              iptables                    │
                    │  TCP → REDIRECT :8080 (mitmproxy)        │
                    │  UDP → NFQUEUE → mark → NAT/CONNMARK     │
                    └─────────────────────────────────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         │                            │                            │
         ▼                            ▼                            ▼
┌─────────────────┐    ┌─────────────────────────┐    ┌───────────────────┐
│  NfqueueHandler │    │     MitmproxyAddon      │    │   MitmproxyAddon  │
│    (nfqueue)    │    │    (transparent)        │    │   (dns@8053)      │
├─────────────────┤    ├─────────────────────────┤    ├───────────────────┤
│ • Non-DNS UDP   │    │ • tls_clienthello       │    │ • dns_request     │
│   (port≠53)     │    │ • request (HTTP/HTTPS)  │    │ • dns_response    │
│ • DNS detection │    │ • tcp_start (raw TCP)   │    │                   │
│   → cache+mark  │    │                         │    │                   │
└─────────────────┘    └─────────────────────────┘    └───────────────────┘
```

## Integration Points

### Handler → Rule Matching Matrix

| Handler Method | Event Type | Available Fields | Can Block? | When to Check |
|---------------|------------|------------------|------------|---------------|
| `tls_clienthello` | https | dst_ip, dst_port, host (SNI), exe, cmdline, cgroup, step | Yes | Before forwarding |
| `request` | http | dst_ip, dst_port, url, method, exe, cmdline, cgroup, step | Yes | Before forwarding |
| `tcp_start` | tcp | dst_ip, dst_port, exe, cmdline, cgroup, step | Yes | At connection start |
| `dns_request` | dns | dst_ip, dst_port, name, exe, cmdline, cgroup, step | Yes | Before forwarding |
| `dns_response` | - | response IPs | No | Cache IPs for correlation |
| `handle_packet` (UDP) | udp | dst_ip, dst_port, exe, cmdline, cgroup, step | Yes | At packet receipt |

### Blocking Mechanisms

| Protocol | Blocked Action | User Experience |
|----------|---------------|-----------------|
| HTTP | Return 403 Forbidden | Clear error page |
| HTTPS | Kill connection | Connection reset |
| TCP | Kill flow | Connection refused |
| DNS | Return REFUSED | Name resolution failed |
| UDP | Drop packet | Timeout |

## DNS Response IP Correlation

### Problem

When a policy allows `github.com:443`, we need to handle:
1. DNS query for `github.com` → ALLOW (matches host rule)
2. TCP connection to `140.82.121.4:443` → ??? (no hostname at `tcp_start`)

Without correlation, TCP connections would be blocked because host rules require a hostname.

### Solution: DNS IP Cache

When DNS resolves an allowed hostname, cache the resulting IPs:

```python
# Data structure
dns_ip_cache: dict[str, tuple[str, float]]  # IP → (hostname, expiry_time)

# On dns_response (after allowing):
#   1. Parse response A/AAAA records
#   2. For each IP: cache[ip] = (query_name, time.now() + ttl)

# On tcp_start:
#   1. Look up dst_ip in dns_ip_cache
#   2. If found and not expired: use cached hostname for matching
#   3. If not found: match only against IP/CIDR rules
```

### Cache Behavior

- **TTL-based expiry**: Respect DNS TTL, cap at reasonable maximum (e.g., 1 hour)
- **Hostname storage**: Store actual hostname, re-match against rules at connection time
- **Wildcard handling**: `api.github.com` cached as-is, matched against `*.github.com` rules
- **Cache misses**: Connections without cached hostname only match IP/CIDR rules

## Design Decisions

### D1: Connections without DNS correlation

**Decision**: Block by default (strict mode).

If a connection arrives to an IP that wasn't resolved through our DNS proxy:
- Could be a direct IP connection (bypassing DNS)
- Could be cached DNS from before proxy started
- Could be a race condition

Users can add explicit IP/CIDR rules for legitimate direct-IP connections.

### D2: Process attribute matching when PID unavailable

**Decision**: Allow if network attributes match, log warning.

BPF map lookup can fail (race condition, process exited). Process attribution is best-effort; network rules are authoritative.

### D3: Per-request vs per-connection checking

- **HTTP**: Check each request (different paths/methods)
- **HTTPS**: Check at ClientHello (have SNI), optionally re-check decrypted requests
- **TCP**: Check once at connection start
- **DNS**: Check each query
- **UDP**: Check each packet

### D4: DNS-over-HTTPS (DoH)

**Decision**: Treat as normal HTTPS.

DoH connections to allowed endpoints are fine. The subsequent connections will be checked normally. Document known DoH endpoints for users who want to block them explicitly.

## Architecture for Testability

### Current Problem

Handlers are tightly coupled to:
- mitmproxy types (`http.HTTPFlow`, `dns.DNSFlow`, etc.)
- BPF state
- Logging

This makes unit testing difficult without running the full proxy.

### Solution: Extract Decision Logic

Create a `PolicyEnforcer` class that:
1. Takes policy matcher and DNS cache as dependencies
2. Provides pure functions for decision-making
3. Returns structured decisions (allow/block + reason)

```python
@dataclass
class Decision:
    allowed: bool
    reason: str
    matched_rule: int | None = None

class PolicyEnforcer:
    def __init__(self, matcher: PolicyMatcher, dns_cache: DNSIPCache):
        self.matcher = matcher
        self.dns_cache = dns_cache

    def check_https(self, dst_ip: str, dst_port: int, sni: str | None,
                    proc_info: dict) -> Decision:
        """Check HTTPS connection. Pure function, easily testable."""
        ...

    def check_http(self, dst_ip: str, dst_port: int, url: str,
                   method: str, proc_info: dict) -> Decision:
        """Check HTTP request. Pure function, easily testable."""
        ...

    def check_tcp(self, dst_ip: str, dst_port: int,
                  proc_info: dict) -> Decision:
        """Check raw TCP connection. Uses DNS cache for hostname."""
        ...

    def check_dns(self, dst_ip: str, dst_port: int, query_name: str,
                  proc_info: dict) -> Decision:
        """Check DNS query."""
        ...

    def check_udp(self, dst_ip: str, dst_port: int,
                  proc_info: dict) -> Decision:
        """Check UDP packet."""
        ...

    def record_dns_response(self, query_name: str, ips: list[str],
                            ttl: int) -> None:
        """Record DNS response IPs for correlation."""
        ...
```

### Handler Integration

Handlers become thin wrappers:

```python
class MitmproxyAddon:
    def __init__(self, bpf: BPFState, enforcer: PolicyEnforcer):
        self.bpf = bpf
        self.enforcer = enforcer

    def request(self, flow: http.HTTPFlow) -> None:
        # Extract data from mitmproxy types
        src_port = flow.client_conn.peername[1]
        dst_ip, dst_port = flow.server_conn.address
        url = flow.request.pretty_url
        method = flow.request.method

        pid = self.bpf.lookup_pid(dst_ip, src_port, dst_port)
        proc_info = get_proc_info(pid)

        # Delegate decision to enforcer
        decision = self.enforcer.check_http(dst_ip, dst_port, url, method, proc_info)

        if not decision.allowed:
            flow.response = http.Response.make(403, f"Blocked: {decision.reason}")
            return

        # Log allowed connection
        proxy_logging.log_connection(type="http", verdict="allow", ...)
```

### Test Structure

```python
# tests/test_policy_enforcer.py

class TestPolicyEnforcer:
    def test_https_allowed_by_host_rule(self):
        policy = "github.com"
        enforcer = PolicyEnforcer(PolicyMatcher(policy), DNSIPCache())

        decision = enforcer.check_https(
            dst_ip="140.82.121.4",
            dst_port=443,
            sni="github.com",
            proc_info={}
        )

        assert decision.allowed

    def test_tcp_allowed_via_dns_cache(self):
        policy = "github.com:22"
        dns_cache = DNSIPCache()
        dns_cache.add("140.82.121.4", "github.com", ttl=300)
        enforcer = PolicyEnforcer(PolicyMatcher(policy), dns_cache)

        decision = enforcer.check_tcp(
            dst_ip="140.82.121.4",
            dst_port=22,
            proc_info={}
        )

        assert decision.allowed

    def test_tcp_blocked_without_dns_cache(self):
        policy = "github.com:22"  # No IP rules
        enforcer = PolicyEnforcer(PolicyMatcher(policy), DNSIPCache())

        decision = enforcer.check_tcp(
            dst_ip="140.82.121.4",
            dst_port=22,
            proc_info={}
        )

        assert not decision.allowed
        assert "no DNS" in decision.reason.lower()
```

## Implementation Plan

### Phase 1: Core Infrastructure

1. **Create `DNSIPCache` class** (`src/proxy/policy/dns_cache.py`)
   - Thread-safe IP → hostname cache
   - TTL-based expiration
   - Add/lookup/cleanup methods

2. **Create `PolicyEnforcer` class** (`src/proxy/policy/enforcer.py`)
   - Pure decision functions for each protocol
   - DNS cache integration
   - Structured `Decision` return type

3. **Add tests for enforcer** (`tests/test_policy_enforcer.py`)
   - Unit tests with mocked dependencies
   - Test all protocol types
   - Test DNS cache correlation

### Phase 2: Handler Integration

4. **Update `MitmproxyAddon`**
   - Add enforcer dependency
   - Integrate `check_http` in `request()`
   - Integrate `check_https` in `tls_clienthello()`
   - Integrate `check_tcp` in `tcp_start()`
   - Integrate `check_dns` in `dns_request()`
   - Add `dns_response()` handler for IP caching

5. **Update `NfqueueHandler`**
   - Add enforcer dependency
   - Integrate `check_udp` in `handle_packet()`
   - Use `pkt.drop()` for blocked packets

6. **Update `main.py`**
   - Load policy from config/environment
   - Create enforcer and pass to handlers

### Phase 3: Testing & Refinement

7. **Integration tests**
   - Test with real mitmproxy in subprocess
   - Verify blocking behavior end-to-end

8. **Logging enhancements**
   - Add verdict field to connection logs
   - Log matched rule for debugging
   - Add policy load/parse logging

### File Structure

```
src/proxy/policy/
├── __init__.py          # Exports
├── types.py             # Rule, AttrValue, etc.
├── parser.py            # Policy parsing
├── matcher.py           # Rule matching
├── dns_cache.py         # NEW: DNS IP correlation cache
└── enforcer.py          # NEW: Policy enforcement decisions

tests/
├── fixtures/
│   ├── policy_flatten.yaml
│   └── policy_match.yaml
├── test_policy.py           # Parser/matcher tests
├── test_dns_cache.py        # NEW: DNS cache tests
└── test_policy_enforcer.py  # NEW: Enforcer tests
```

## Open Questions

### Q1: Policy source

Where does the policy come from?
- Environment variable (`EGRESS_POLICY`)
- File path (`EGRESS_POLICY_FILE`)
- Control socket command

**Recommendation**: Environment variable for GitHub Actions, file path for local testing.

### Q2: Policy reload

Should policy be reloadable at runtime?
- Adds complexity
- Useful for debugging

**Recommendation**: No hot reload in v1. Restart proxy to change policy.

### Q3: Audit mode

Should there be a mode that logs but doesn't block?
- Useful for policy development
- "Dry run" before enforcement

**Recommendation**: Yes, add `EGRESS_MODE=audit|enforce` option.

### Q4: Default policy

What happens if no policy is provided?
- Block all (secure default)
- Allow all (permissive default)
- Error (explicit configuration required)

**Recommendation**: Allow all with warning. This maintains backward compatibility and makes adoption gradual.
