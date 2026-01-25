# Policy Syntax Design

Design document for the egress filter allowlist/blocklist syntax.

## Design Constraints

1. **Inline in workflow file** - Policy must be defined directly in the GitHub Actions workflow YAML, not in a separate config file. This is because:
   - `actions/checkout` hasn't run yet when egress-filter starts
   - We want to monitor network activity from the very beginning (including checkout)
   - Consequence: no syntax highlighting in editors (it's a string blob to GitHub Actions)

2. **One rule per line** - Each rule is a single line. No multi-line structured formats. This:
   - Keeps parsing simple
   - Makes diffs readable
   - Feels natural for a list of rules

3. **Human readable/writable first** - The syntax should be designed for humans, not machines. This means:
   - Not a general-purpose serialization format (JSON, YAML, TOML, etc.)
   - Prioritize readability and ease of typing over parse simplicity
   - Key-value pairs are acceptable if they improve clarity (e.g., `port=443`)

4. **Familiar conventions** - Use widely recognized syntax patterns:
   - `*` for wildcards
   - `#` for comments (following YAML convention, since the policy is embedded in YAML)

5. **Sections via headers** - Rules can be grouped under headers that set defaults:
   - Headers use bracket syntax: `[:443]`, `[:53/udp]`, `[GET|HEAD]`
   - Headers contain attributes only (no target)
   - Rules inherit attributes from the most recent header
   - Each header is a full reset, not cumulative with previous headers
   - There's an implicit default header at the top: `[]` (port 443, TCP, GET|HEAD for URLs)
   - `[]` explicitly resets to implicit defaults
   - A rule only needs to specify what it adds/overrides from the header

6. **Allowlist-only model** - Default deny, explicit allows:
   - Everything is blocked by default
   - All rules are allows (no block rules in v1)
   - Skipped block rules for simplicity - can revisit if users request it
   - If block rules are added later, the model would be:
     - Block rules always win (hard veto, checked first)
     - Allow rules use union semantics (any match = allowed)
     - No ordering or specificity concerns

7. **Rules are selectors, not policies** - A rule is a complete selector, not "selector + action":
   - All parts of a rule (domain, port, protocol, etc.) are matching criteria
   - A connection must match ALL parts of a rule to be selected by it
   - `*.github.com port=443` means "github.com subdomains on port 443", not "for github.com, policy is port 443"

8. **Union semantics for allow rules** - Order-independent matching:
   - A connection is allowed if it fully matches ANY allow rule
   - Allow rules don't interact with each other - they're independent selectors

9. **Lenient parsing by default** - Invalid rules are skipped, not fatal:
   - Invalid rule → warning annotation, rule skipped
   - Safe because allowlist model: skipped rule = less allowed = fails closed
   - Traffic that would have matched the bad rule gets blocked
   - Job may fail later with connection error, but warning points to the cause
   - Optional strict mode (`on-invalid-rule: fail`) for those who want parse-time failure

10. **Target is the only required field** - Every rule must have a target:
    - IP address: `93.184.216.34` (IPv4 only)
    - CIDR block: `10.0.0.0/8` (IPv4 only)
    - Hostname: `github.com`
    - URL: `https://github.com/owner/repo/path`
    - All other attributes (port, protocol, etc.) are optional filters
    - No IPv6 support - blocked at kernel level by design (avoids `[::1]:443` parsing complexity)

11. **Wildcard matching for hostnames** - `*.` prefix only:
    - `*.github.com` - valid (matches any subdomain(s))
    - `*a.github.com` - invalid
    - `a*.github.com` - invalid
    - `github.*` - invalid
    - `git*hub.com` - invalid
    - The ONLY valid form is `*.` followed by domain (entire first label is wildcard)
    - Wildcards NOT allowed in hostname part of URLs: `https://*.github.com/foo` - invalid

12. **Explicit hostname matching** - No implicit subdomain inclusion:
    - `github.com` matches only `github.com` exactly
    - `*.github.com` matches subdomains only (e.g., `api.github.com`), not `github.com` itself
    - To allow both, need two rules: `github.com` and `*.github.com`
    - Matches StepSecurity Harden Runner's behavior (familiar to users of similar tools)

13. **Port defaults to 443** - Secure by default:
    - Most CI egress is HTTPS (443)
    - `github.com` means `github.com:443`
    - `github.com:22` for explicit SSH
    - `github.com:*` for any port

14. **Protocol defaults to TCP** - UDP as suffix modifier:
    - `github.com` → TCP:443
    - `8.8.8.8:53/udp` → UDP:53
    - `dns.google:*/udp` → UDP any port
    - `/udp` requires explicit port (no `dns.google/udp` - must be `dns.google:53/udp` or `dns.google:*/udp`)
    - `/tcp` allowed but unnecessary (it's the default)

    **DNS matching semantics**: DNS events have two dimensions - the DNS server and the query name.
    - **IP rules** (e.g., `8.8.8.8:53/udp`) match the **DNS server IP** - allows any query to that server
    - **Hostname rules** (e.g., `*.github.com:53/udp`) match the **query name** - allows queries for those domains to any server
    - Both can be combined: IP rules restrict which DNS servers, hostname rules restrict which domains
    - Example: `8.8.8.8:53/udp` allows `dig evil.com @8.8.8.8` (any query to Google DNS)
    - Example: `github.com:53/udp` allows `dig github.com @1.1.1.1` (github.com query to any server)

15. **URL rules require scheme prefix** - Clear visual distinction:
    - `https://github.com/owner/repo/*` - URL rule with path
    - `http://example.com/api/*` - explicit HTTP
    - `github.com` - domain rule (no path matching)
    - Disambiguates parsing: `github.com/foo` would be ambiguous without scheme
    - Open question: is `https://github.com` (no path) valid? equivalent to domain rule? root only? error?

16. **HTTP method as prefix for URL rules**:
    - `POST https://api.github.com/repos/*/issues` - only POST
    - `GET https://api.github.com/repos/*/releases` - only GET
    - `https://github.com/*` - GET|HEAD only (default when omitted)
    - `* https://github.com/*` - any method (explicit wildcard)
    - Case: normalize to uppercase internally, accept any case in input

17. **Pipe (`|`) for alternatives in limited places**:
    - Methods: `GET|HEAD|POST https://api.github.com/*`
    - Ports: `github.com:80|443`
    - NOT allowed for hosts/IPs/URLs - use multiple rules instead
    - Keeps rules readable: one target per line

18. **Query strings and fragments rejected** - URLs match on path only:
    - `https://api.github.com/search?q=test` - invalid (rejected at parse time)
    - Write `https://api.github.com/search` instead (matches any query string at runtime)
    - Query strings are highly dynamic (pagination, tokens, timestamps)
    - Filtering on them would be tedious and fragile
    - Rejecting makes it explicit that query params aren't filtered

19. **URL path wildcards: position-dependent `*`**:
    - `*` at end of path → match any remaining path (greedy)
    - `*` elsewhere in path → match exactly one segment
    - Partial segment matching allowed (e.g., `v*.zip`)
    - Examples:
      - `https://github.com/*` - any path on github.com
      - `https://github.com/*/releases` - one segment, then literal "releases"
      - `https://github.com/*/*/releases` - two segments, then "releases"
      - `https://cdn.example.com/v*.zip` - partial segment match
    - This is slightly unconventional but intuitive: "end = anything below, middle = one segment"

20. **Path-only rules under URL headers** - Convenience for API rules:
    - Headers can contain a base URL: `[https://api.github.com/v1/repos]`
    - Rules starting with `/` are paths concatenated to the header base
    - `GET /*/releases` under that header → `https://api.github.com/v1/repos/*/releases`
    - Leading `/` required for path rules (clarity, easy to parse)
    - Double slashes from concatenation normalize to single slash
    - If header has no path, rule path is absolute from root
    - Non-`/` rules still work as full domain/IP rules in the same policy
    - **Error if no URL context**: path-only rules invalid in default context or after `[]` reset
    - The implicit default header has no URL base; `[]` resets to this state

## Future Considerations

### VS Code extension for syntax highlighting

A VS Code extension could provide syntax highlighting for policies embedded in workflow YAML:
- Use TextMate grammar injection to highlight inside `policy: |` blocks
- Scope injection to files matching `.github/workflows/*.yml` with `uses: */egress-filter@*`
- The grammar itself is simple: comments (`#`), headers (`[...]`), hostnames, URLs, attributes

Limitations:
- Requires users to install the extension
- GitHub's web editor and PR diffs won't benefit (always shows plain string)
- JetBrains IDEs would need a separate plugin (IntelliLang injection)

### Standalone validation CLI/library

A CLI tool to validate policies independently of the GitHub Action:

```bash
egress-filter validate policy.txt
egress-filter check --stdin < policy.txt
```

**Error messages:** Consider two-pass approach or permissive parsing with strict validation to provide helpful error messages:
- "Query strings not allowed, remove `?...` from URL"
- "/udp requires a port, use `:53/udp` or `:*/udp`"

**Lint warnings** (not errors):
- "*.github.com without github.com - did you mean to allow root domain too?"
- "Path rule without URL header context"

## Open Questions

### Presets and variables

- How to reference built-in presets (e.g., `@github-actions`)?
- Could `@name` be a general syntax for "variables" defined elsewhere?
  - Built-in: `@docker`, `@container`, `@host` for cgroup patterns
  - Built-in: `@github-actions` for required GHA infrastructure endpoints
  - User-defined: `@my-api-servers` expanding to a list of domains?
- This could unify presets, cgroup abstractions, and user-defined groups

### Rule attributes (optional filters)

21. **Supported attributes**:
    - `exe=` - Executable path (e.g., `exe=/usr/bin/node`, `exe=*/node`)
    - `arg=` - Match any argument in argv
    - `arg[N]=` - Match specific argument by index (0-based, `arg[0]` is typically the command)
    - `step=` - GitHub Actions step (matches `GITHUB_ACTION` env var)
      - If step has `id:` set, use that: `step=my-build`
      - If no `id:`, we translate action refs: `step=actions/setup-node` → `__actions_setup-node(_\d+)?`
      - `run:` steps without `id:` get `__run`, `__run_2`, etc.
      - Note: explicit `id:` overrides action name - can't match by action ref if `id:` is set
    - `cgroup=` - Process cgroup path, with abstractions like `@docker`, `@host`

22. **Quoting in attribute values** - Three modes:
    - Unquoted: `exe=*/node` - wildcards active, no spaces/`#` allowed
    - Double quotes: `arg="hello world"` - literal (no wildcards), spaces OK
    - Backticks: `` arg=`hello *.txt` `` - wildcards active, spaces OK

    | Need spaces? | Need wildcards? | Syntax |
    |--------------|-----------------|--------|
    | No | No | `exe=/usr/bin/node` |
    | No | Yes | `exe=*/node` |
    | Yes | No | `arg="hello world"` |
    | Yes | Yes | `` arg=`hello *.txt` `` |

    Quoting only applies to attribute values, not targets (URLs, hostnames, paths).

23. **No KV-equivalent for positional syntax** - Keep it simple:
    - Port, protocol, method have shorthand syntax only (`:443`, `/udp`, `GET`)
    - No `port=443`, `proto=udp`, `method=GET` alternatives
    - Avoids conflicts like `github.com:443 port=80`
    - KV syntax reserved for process attributes (`exe=`, `arg=`, etc.)

24. **No duplicate fields in a rule** - Flat attribute set:
    - `github.com:443 port=80` - error (port specified twice)
    - `github.com exe=/bin/a exe=/bin/b` - error (exe specified twice)
    - `GET https://... method=POST` - error (method twice, if KV existed)
    - Header + rule override is OK: header provides defaults, rule overrides
    - This is a semantic validation error, not a parse error

25. **Case sensitivity**:
    - Hostnames: case-insensitive (per DNS spec) - `GitHub.com` matches `github.com`
    - HTTP methods: case-insensitive input, normalized to uppercase - `get` → `GET`
    - URL paths: case-sensitive (per HTTP convention) - `/Repos` ≠ `/repos`
    - Attribute values: case-sensitive by default - `exe=/usr/bin/Node` ≠ `exe=/usr/bin/node`

## Example Policy

```yaml
# In .github/workflows/ci.yml
- uses: your/egress-filter@v1
  with:
    policy: |-
      # Package registries
      registry.npmjs.org
      *.npmjs.org
      pypi.org
      files.pythonhosted.org
      
      # GitHub
      github.com
      *.github.com
      *.githubusercontent.com
      
      # GitHub API with path restrictions
      [https://api.github.com]
      GET /repos/*/releases
      GET /repos/*/tags
      POST /repos/*/issues
      
      # Docker registry
      *.docker.io
      
      # DNS (UDP)
      [:53/udp]
      8.8.8.8
      1.1.1.1
      
      # SSH access
      [:22]
      github.com
      
      # Internal network (any port)
      [:*]
      10.0.0.0/8
```
