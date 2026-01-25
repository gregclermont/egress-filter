# Policy Matching Algorithms

Implementation notes for efficient rule matching at runtime.

## Expected Scale and Approach

**Expected rule counts**: <100 rules for typical workflows, low hundreds at most with presets. This is limited by:
- User tolerance for writing long configs
- Workflow files being a poor place for verbose network allowlists
- Even fine-grained rules tend to cluster around a few services

**Performance context** (100 rules, per connection):

| Implementation | Time per match | Notes |
|----------------|----------------|-------|
| Naive linear scan | 5-50 µs | Python loop with string ops |
| Medium optimized | 1-10 µs | Pre-compiled regexes, radix tree for IPs |
| Hardcore optimized | 0.1-1 µs | Native code, indexed lookups |

**Why it doesn't matter (yet)**:
- Typical CI job: 100-1000 connections total
- TLS handshake: 10-100 ms (matching is 0.05% of this)
- mitmproxy overhead: 1-5 ms per request
- Total matching time for entire job: ~5 ms worst case

Real time goes to: TLS interception, BPF map lookups, `/proc` reads, logging I/O.

**Recommendation**: Start with the simplest correct implementation. Add instrumentation to measure real-world performance. Optimize only if data shows it's needed.

```python
def match_connection(conn):
    for rule in rules:  # 100 iterations is fine
        if rule.matches(conn):
            return True
    return False
```

The rest of this document is reference material for if/when optimization becomes necessary.

---

## Overview

The policy syntax is flexible (wildcards, CIDR ranges, path patterns, process attributes), but matching must be fast since every connection is checked. This document outlines data structures and algorithms for efficient matching.

## Matching Requirements

A connection has these properties to match against:
- **Destination IP** (IPv4 only)
- **Destination port**
- **Protocol** (TCP/UDP)
- **Hostname** (from SNI for TLS, Host header for HTTP, DNS query)
- **URL path** (for HTTP/HTTPS)
- **HTTP method** (for HTTP/HTTPS)
- **Process attributes**: exe, argv, step, cgroup

A rule matches if ALL of its specified fields match the connection. If a field is absent from the rule, it's not checked (implicit wildcard).

## Data Structures by Field Type

### IP Addresses and CIDR Blocks

**Problem**: Match an IP against many exact IPs and CIDR ranges.

**Solution**: Radix tree (Patricia trie) specialized for IP prefixes.

- O(32) lookup for IPv4 (one bit per tree level, max 32 levels)
- Handles both exact IPs and CIDR ranges naturally
- Libraries: `py-radix`, `pytricia`

```python
import radix

rtree = radix.Radix()

# Add rules
rtree.add("93.184.216.34/32")  # exact IP
rtree.add("10.0.0.0/8")        # CIDR block

# Lookup
node = rtree.search_best("10.1.2.3")  # returns 10.0.0.0/8 node
```

**Note**: Each radix node stores a reference to the rule(s) that match that prefix. Multiple rules may share a prefix.

### Hostnames with Wildcards

**Problem**: Match `api.github.com` against `api.github.com` (exact) and `*.github.com` (wildcard).

**Solution**: Reverse-label trie.

1. Split hostname into labels: `api.github.com` → `["api", "github", "com"]`
2. Reverse: `["com", "github", "api"]`
3. Walk trie from root, checking for wildcards at each level

```
root
 └─ com
     └─ github
         ├─ [*]  ← wildcard rule for *.github.com
         └─ api  ← exact rule for api.github.com
```

**Lookup for `api.github.com`**:
1. Start at root, go to `com`
2. Go to `github`
3. Check `[*]` node → matches `*.github.com` rule
4. Go to `api` → matches exact `api.github.com` rule
5. Return all matching rules

**Complexity**: O(L) where L = number of labels in hostname.

### Ports

**Problem**: Match port 443 against exact ports (443) and wildcard (*).

**Solution**: Simple hash lookup + wildcard flag.

```python
class PortMatcher:
    def __init__(self):
        self.exact_ports = {}  # port -> set of rules
        self.wildcard_rules = set()  # rules with :*
    
    def match(self, port):
        matches = set(self.wildcard_rules)
        if port in self.exact_ports:
            matches |= self.exact_ports[port]
        return matches
```

For pipe alternatives (`80|443`), index the rule under both ports.

### URL Paths with Wildcards

**Problem**: Match `/repos/owner/repo/releases` against patterns like:
- `/repos/*/releases` (one segment wildcard)
- `/repos/*` (greedy wildcard at end)
- `/repos/*/v*.zip` (partial segment)

**Solution**: Segment-by-segment matching with backtracking for partial segments.

1. Split path into segments: `/repos/owner/repo/releases` → `["repos", "owner", "repo", "releases"]`
2. For each rule pattern, walk segments:
   - Literal: must match exactly
   - `*` in middle: match any one segment
   - `*` at end: match all remaining
   - Partial (e.g., `v*.zip`): regex match on segment

**Optimization**: Index by first N literal segments.

```python
# Index by first literal segment
path_index = {
    "repos": [rule1, rule2, rule3],
    "api": [rule4, rule5],
}

# Rules starting with wildcard go in a separate list
wildcard_prefix_rules = [rule6, rule7]
```

For `/repos/owner/repo/releases`:
1. Check `path_index["repos"]` → get candidate rules
2. Also check `wildcard_prefix_rules`
3. Run full pattern match on candidates only

**Complexity**: O(S × P) where S = segments in path, P = pattern segments, but indexing reduces P to relevant rules.

### HTTP Methods

**Problem**: Match request method against `GET`, `GET|HEAD|POST`, or `*`.

**Solution**: Bitmask comparison.

```python
METHOD_BITS = {
    "GET": 0b00000001,
    "HEAD": 0b00000010,
    "POST": 0b00000100,
    "PUT": 0b00001000,
    "DELETE": 0b00010000,
    "PATCH": 0b00100000,
    "OPTIONS": 0b01000000,
    "*": 0b11111111,
}

class MethodMatcher:
    def __init__(self, methods):
        # methods = ["GET", "HEAD"] or ["*"]
        self.mask = 0
        for m in methods:
            self.mask |= METHOD_BITS[m]
    
    def matches(self, method):
        return bool(self.mask & METHOD_BITS.get(method, 0))
```

**Complexity**: O(1).

### Process Attributes (exe, arg, step, cgroup)

**Problem**: Match process metadata against patterns like `exe=*/node`, `arg[0]=npm`, `step=build`.

**Solution**: Two-tier approach.

**Tier 1 - Exact match index**:
```python
exe_exact_index = {
    "/usr/bin/node": [rule1, rule2],
    "/usr/bin/npm": [rule3],
}
```

**Tier 2 - Wildcard patterns** (linear scan, but small set):
```python
exe_wildcard_patterns = [
    ("*/node", rule4),
    ("*/npm", rule5),
]
```

**Optimization**: Most rules will have exact values or simple suffix wildcards. For suffix wildcards like `*/node`:
- Index by suffix: `{".../node": [rules]}`
- On lookup, extract suffix from exe path

**Complexity**: O(1) for exact, O(W) for wildcard patterns where W = count of wildcard rules.

## Combined Matching Strategy

### Rule Indexing at Load Time

When the policy is parsed, build indices:

```python
class PolicyIndex:
    def __init__(self, rules):
        self.ip_radix = radix.Radix()
        self.host_trie = HostnameTrie()
        self.port_index = PortIndex()
        self.path_index = PathIndex()
        self.method_matchers = {}
        self.attr_indices = {
            "exe": AttributeIndex(),
            "arg": AttributeIndex(),
            "step": AttributeIndex(),
            "cgroup": AttributeIndex(),
        }
        
        for rule in rules:
            self._index_rule(rule)
```

### Connection Matching at Runtime

```python
def match_connection(self, conn):
    """Return True if any rule allows this connection."""
    
    # Stage 1: Get candidate rules by target (IP or hostname)
    if conn.hostname:
        candidates = self.host_trie.match(conn.hostname)
    else:
        candidates = self.ip_radix.match(conn.dst_ip)
    
    if not candidates:
        return False
    
    # Stage 2: Filter by port
    candidates = [r for r in candidates 
                  if r.matches_port(conn.dst_port)]
    
    if not candidates:
        return False
    
    # Stage 3: Filter by protocol
    candidates = [r for r in candidates 
                  if r.matches_protocol(conn.protocol)]
    
    if not candidates:
        return False
    
    # Stage 4: Filter by URL path (if applicable)
    if conn.url_path and any(r.has_path_pattern for r in candidates):
        candidates = [r for r in candidates 
                      if r.matches_path(conn.url_path)]
    
    if not candidates:
        return False
    
    # Stage 5: Filter by HTTP method (if applicable)
    if conn.http_method and any(r.has_method_filter for r in candidates):
        candidates = [r for r in candidates 
                      if r.matches_method(conn.http_method)]
    
    if not candidates:
        return False
    
    # Stage 6: Filter by process attributes
    for attr in ["exe", "arg", "step", "cgroup"]:
        attr_value = getattr(conn, attr, None)
        if attr_value:
            candidates = [r for r in candidates 
                          if r.matches_attr(attr, attr_value)]
        if not candidates:
            return False
    
    return len(candidates) > 0
```

### Optimization: Rule Ordering

Process stages in order of selectivity (most filtering first):

1. **Target (IP/hostname)** - Usually most selective
2. **Port** - Very selective (most rules specify 443)
3. **Protocol** - Binary filter (TCP/UDP)
4. **Path** - Selective for URL rules
5. **Method** - Moderate selectivity
6. **Attributes** - Least common, check last

### Optimization: Early Termination

Since we use union semantics (any match = allowed), we can:
- Return `True` immediately when a rule with no further filters is matched
- Skip remaining stages if a "simple" rule (no path/method/attributes) matched in stage 3

```python
# After stage 3 (protocol filter)
simple_rules = [r for r in candidates 
                if not r.has_path_pattern 
                and not r.has_method_filter 
                and not r.has_attributes]
if simple_rules:
    return True  # Early exit: simple rule matched
```

## Complexity Summary

| Field | Data Structure | Lookup Complexity |
|-------|---------------|-------------------|
| IP/CIDR | Radix tree | O(32) = O(1) |
| Hostname | Reverse-label trie | O(L) labels |
| Port | Hash + wildcard set | O(1) |
| Protocol | Direct comparison | O(1) |
| URL Path | Segment trie + pattern match | O(S) segments |
| HTTP Method | Bitmask | O(1) |
| Attributes | Hash + wildcard scan | O(1) to O(W) |

**Overall**: O(L + S + W) per connection, where:
- L = hostname label count (typically 2-4)
- S = URL path segment count (typically 2-6)
- W = wildcard attribute rule count (typically small)

In practice, most connections match in O(1) to O(10) operations.

## Libraries

- **py-radix** / **pytricia**: IP/CIDR radix trees
- **Hyperscan** (optional): Intel's regex engine for high-throughput pattern matching
- **datrie**: Efficient trie implementation for hostname matching

## Future Optimizations

### Compiled Matchers

For hot paths, compile patterns to native code:
- Regex → compiled regex object
- Simple wildcards → string operations (startswith, endswith)
- Complex patterns → bytecode or Cython

### Connection Caching

Cache recent match results:
```python
# LRU cache keyed by (dst_ip, dst_port, protocol, hostname)
# Don't cache path/method/attributes (too variable)
connection_cache = LRUCache(maxsize=10000)
```

### Bloom Filter Pre-check

For large rulesets, use a Bloom filter to quickly reject non-matching connections:
```python
# Bloom filter contains all allowed hosts/IPs
if hostname not in bloom_filter:
    return False  # Definitely not allowed
# Else: might be allowed, do full check
```

## Testing Considerations

- Benchmark with realistic rule counts (10, 100, 1000 rules)
- Test with high connection rates (1000+ conn/sec)
- Profile to find actual bottlenecks before optimizing
- Ensure correctness before performance (matching semantics are complex)
