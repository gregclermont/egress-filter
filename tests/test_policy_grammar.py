"""
Property-based tests for policy syntax grammar.

Uses parsimonious for PEG parsing and hypothesis for fuzzing.

Run with: pytest tests/test_policy_grammar.py -v
"""

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from parsimonious.exceptions import ParseError
from parsimonious.grammar import Grammar

# =============================================================================
# Grammar Definition (inline for now, could load from .peg file)
# =============================================================================

GRAMMAR = Grammar(r"""
policy          = (line newline)* line?
line            = header / rule / comment_only / blank
blank           = ws*
comment_only    = ws* comment
comment         = "#" ~"[^\n]*"
inline_comment  = ws+ comment
newline         = "\n" / "\r\n"
ws              = " " / "\t"

header          = ws* "[" header_attrs? "]" inline_comment? ws*
header_attrs    = url_base / method_attr / port_proto_attr
url_base        = scheme "://" url_host url_port? url_path?
port_proto_attr = port_attr proto_attr?

rule            = ws* (url_rule / path_rule / cidr_rule / ip_rule / host_rule) port_proto_attr? kv_attrs? inline_comment? ws*

url_rule        = (method_attr ws+)? scheme "://" url_host url_port? url_path
url_host        = ipv4 / wildcard_host / hostname
scheme          = "https" / "http"
url_port        = ":" port_list
url_path        = "/" path_rest
path_rest       = ~"[a-zA-Z0-9_.~*/%+-]*"

path_rule       = (method_attr ws+)? "/" path_rest

host_rule       = wildcard_host / exact_host
wildcard_host   = subdomain_wildcard / label_wildcard
subdomain_wildcard = "*." wildcard_label "." hostname_or_tld
label_wildcard  = wildcard_label "." hostname_or_tld
wildcard_label  = ~"[a-zA-Z0-9-]*\\*[a-zA-Z0-9*-]*"
exact_host      = !ipv4_lookahead hostname !(":/")
hostname        = (hostname_part ".")+ tld
hostname_or_tld = hostname / tld
tld             = ~"[a-zA-Z][a-zA-Z0-9]*"
hostname_part   = ~"[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?" / ~"[a-zA-Z0-9]"

ip_rule         = ipv4 !("." / "/")
cidr_rule       = ipv4 "/" cidr_mask

ipv4            = octet "." octet "." octet "." octet !(".")
ipv4_lookahead  = ~"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"
octet           = ~"25[0-5]" / ~"2[0-4][0-9]" / ~"1[0-9][0-9]" / ~"[1-9][0-9]" / ~"[0-9]"
cidr_mask       = ~"3[0-2]" / ~"[12][0-9]" / ~"[0-9]"

kv_attrs        = (ws+ kv_attr)*
port_proto_attr = port_attr proto_attr?
port_attr       = ":" port_list
port_list       = port_value ("|" port_value)*
port_value      = "*" / ~"[0-9]+"

proto_attr      = "/" protocol
protocol        = "udp" / "tcp"

method_attr     = method ("|" method)*
method          = "GET" / "HEAD" / "POST" / "PUT" / "DELETE" / "PATCH" / "OPTIONS" / "*"

kv_attr         = kv_key "=" kv_value
kv_key          = arg_indexed / "image" / "action" / "step" / "cgroup" / "exe" / "arg"
arg_indexed     = "arg[" ~"[0-9]+" "]"
kv_value        = backtick_value / quoted_value / unquoted_value
backtick_value  = "`" ~"[^`]*" "`"
quoted_value    = "\"" ~"[^\"]*" "\""
unquoted_value  = ~"[^\\s#]+"
""")


def parse(text: str):
    """Parse a policy string, return the parse tree or raise ParseError."""
    return GRAMMAR.parse(text)


def parses(text: str) -> bool:
    """Return True if text parses successfully."""
    try:
        parse(text)
        return True
    except ParseError:
        return False


# =============================================================================
# Valid Examples
# =============================================================================

VALID_RULES = [
    # Basic hostnames
    "github.com",
    "api.github.com",
    "a.b.c.d.example.com",
    # Wildcard hostnames
    "*.github.com",
    "*.a.b.github.com",
    # Label pattern wildcards (fnmatch in first label)
    "derp*.tailscale.com",
    "*-prod.example.com",
    "api*.example.com",
    "*api*.example.com",
    # Subdomain + label pattern wildcards
    "*.derp*.tailscale.com",
    "*.*-prod.example.com",
    # Hostnames with ports
    "github.com:443",
    "github.com:22",
    "github.com:80|443",
    "github.com:*",
    # Hostnames with protocol
    "github.com:22/tcp",
    "dns.google:53/udp",
    "dns.google:*/udp",
    # IP addresses
    "8.8.8.8",
    "192.168.1.1",
    "0.0.0.0",
    "255.255.255.255",
    # IPs with ports
    "8.8.8.8:53",
    "8.8.8.8:53/udp",
    "1.1.1.1:53|853",
    # CIDR blocks
    "10.0.0.0/8",
    "192.168.0.0/16",
    "172.16.0.0/12",
    "0.0.0.0/0",
    # CIDR with port and protocol
    "10.0.0.0/8:*",
    "10.0.0.0/8:53/udp",
    # URLs
    "https://github.com/",
    "https://github.com/*",
    "https://github.com/owner/repo",
    "https://github.com/*/releases",
    "https://github.com/*/*/releases",
    "https://*.github.com/path",
    "https://productionresultssa*.blob.core.windows.net/*",
    "http://example.com/api/v1/*",
    "https://cdn.example.com/v1.2.3.zip",
    # URLs with methods
    "GET https://api.github.com/",
    "POST https://api.github.com/repos/*/issues",
    "GET|HEAD https://example.com/*",
    "GET|HEAD|POST https://api.example.com/*",
    "* https://example.com/*",
    # URLs with ports
    "https://example.com:8080/api/*",
    "https://example.com:*/api/*",
    "https://example.com:80|443/api/*",
    # Headers
    "[:443]",
    "[:22]",
    "[:53/udp]",
    "[:80|443]",
    "[:*/udp]",
    "[GET]",
    "[GET|HEAD]",
    "[GET|HEAD|POST]",
    "[]",
    # URL base headers
    "[https://api.github.com]",
    "[https://api.github.com/v1]",
    "[https://api.github.com/v1/repos]",
    "[https://example.com:8080]",
    "[https://example.com:8080/api]",
    "[https://productionresultssa*.blob.core.windows.net]",
    # Path-only rules (valid syntax, semantic validation separate)
    "/repos/*/releases",
    "GET /repos/*/releases",
    "POST /repos/*/issues",
    "GET|HEAD /users/*",
    "/* ",
    "/v1/api/*",
    # Comments
    "# this is a comment",
    "  # indented comment",
    "github.com # inline comment",
    "[:443] # header comment",
    # Key-value attributes
    "github.com exe=/usr/bin/curl",
    "github.com:443 exe=/usr/bin/node step=build",
    "github.com exe=*/node",
    "github.com arg=--upload",
    "github.com arg=*.json",
    "github.com arg[0]=node",
    "github.com arg[1]=build",
    "github.com arg[0]=*/python*",
    # Quoted attribute values
    'github.com arg="hello world"',
    'github.com exe="/path/with spaces/node"',
    'github.com arg[1]="npm install"',
    # Backtick quoted (wildcards active)
    "github.com arg=`hello *.txt`",
    "github.com arg=`foo bar`",
    "github.com arg[0]=`* --version`",
    # Step and cgroup attributes
    "registry.npmjs.org step=actions/setup-node",
    "registry.npmjs.org step=my-build",
    "github.com cgroup=@docker",
    "github.com cgroup=@host",
    "*.docker.io cgroup=*docker*",
    # Multiple attributes
    "github.com:22 exe=/usr/bin/git step=checkout",
    "registry.npmjs.org step=install arg[0]=npm",
    # Whitespace handling
    "  github.com",
    "github.com  ",
    "  github.com  ",
]

VALID_POLICIES = [
    # Empty
    "",
    # Single rule
    "github.com",
    # Multiple rules
    """github.com
api.github.com
*.githubusercontent.com""",
    # With headers
    """[:443]
github.com
api.github.com

[:53/udp]
8.8.8.8
1.1.1.1""",
    # With comments
    """# GitHub access
github.com
*.github.com

# DNS servers
[:53/udp]
8.8.8.8  # Google
1.1.1.1  # Cloudflare""",
    # Complex policy
    """# Egress policy for CI build

# Package registries
registry.npmjs.org
*.npmjs.org
pypi.org
files.pythonhosted.org

# GitHub
github.com
*.github.com
*.githubusercontent.com

# API access
GET https://api.github.com/repos/*/releases
POST https://api.github.com/repos/*/issues

# DNS
[:53/udp]
8.8.8.8
1.1.1.1

# Internal network
[:*/tcp]
10.0.0.0/8
""",
    # Policy with URL base headers and path rules
    """# GitHub API
[https://api.github.com/repos]
GET /*/releases
GET /*/tags
POST /*/issues

# Back to regular rules
[]
registry.npmjs.org
*.npmjs.org

# Another API
[https://registry.npmjs.org]
GET /*
""",
]


# =============================================================================
# Invalid Examples
# =============================================================================

INVALID_RULES = [
    # Bare wildcard
    "*",
    # Incomplete wildcard hostname
    "*.",
    "*..",
    # Invalid wildcard positions (wildcards only allowed in first label)
    "github.*",
    "api.derp*.example.com",  # Wildcard in second label (not first)
    "github.com*",
    # Missing target
    ":443",
    ":53/udp",
    # Empty port
    "github.com:",
    # Path without scheme
    "github.com/path",
    "github.com/path/to/resource",
    # Scheme without host
    "https://",
    "http://",
    # UDP without port
    "github.com/udp",
    "dns.google/udp",
    # Target in header (non-URL)
    "[github.com]",
    # Invalid CIDR
    "10.0.0.0/33",
    "10.0.0.0/",
    # Invalid IP
    "256.0.0.0",
    "1.2.3.256",
    "1.2.3",
    "1.2.3.4.5",
    # Invalid characters in hostname
    "github_com",
    "github..com",
    "-github.com",
    "github-.com",
    # Unknown attribute keys
    "github.com typo=foo",
    "github.com exee=/usr/bin/curl",
    "github.com unknown=value",
]


# =============================================================================
# Tests
# =============================================================================


class TestValidExamples:
    """Test that all valid examples parse successfully."""

    @pytest.mark.parametrize("rule", VALID_RULES)
    def test_valid_rule(self, rule):
        assert parses(rule), f"Should parse: {rule!r}"

    @pytest.mark.parametrize("policy", VALID_POLICIES)
    def test_valid_policy(self, policy):
        assert parses(policy), f"Should parse policy:\n{policy}"


class TestInvalidExamples:
    """Test that all invalid examples fail to parse."""

    @pytest.mark.parametrize("rule", INVALID_RULES)
    def test_invalid_rule(self, rule):
        assert not parses(rule), f"Should NOT parse: {rule!r}"


class TestEdgeCases:
    """Test specific edge cases and boundary conditions."""

    def test_minimal_hostname(self):
        assert parses("a.co")
        assert parses("x.y")

    def test_minimal_wildcard(self):
        assert parses("*.co")
        assert parses("*.a.co")

    def test_port_boundaries(self):
        assert parses("github.com:0")
        assert parses("github.com:65535")
        assert parses("github.com:99999")  # We don't validate port range

    def test_cidr_boundaries(self):
        assert parses("0.0.0.0/0")
        assert parses("255.255.255.255/32")
        assert not parses("10.0.0.0/33")

    def test_ip_boundaries(self):
        assert parses("0.0.0.0")
        assert parses("255.255.255.255")
        assert not parses("256.0.0.0")

    def test_empty_header_resets_defaults(self):
        assert parses("[]")

    def test_method_case_sensitivity(self):
        # Grammar currently requires uppercase
        assert parses("GET https://example.com/")
        assert not parses("get https://example.com/")

    def test_url_path_wildcards(self):
        # End of path - greedy
        assert parses("https://github.com/*")
        # Middle of path - single segment
        assert parses("https://github.com/*/releases")
        # Multiple wildcards
        assert parses("https://github.com/*/*/releases")
        # Partial segment
        assert parses("https://cdn.example.com/v*.zip")

    def test_pipe_alternatives(self):
        # Ports
        assert parses("github.com:80|443")
        assert parses("github.com:22|80|443")
        # Methods
        assert parses("GET|HEAD https://example.com/")
        assert parses("GET|HEAD|POST https://example.com/")

    def test_inline_comments(self):
        assert parses("github.com # comment")
        assert parses("[:443] # header comment")
        assert parses("8.8.8.8:53/udp # DNS")

    def test_url_with_query_strings_rejected(self):
        # Query strings are rejected - matches any query at runtime
        assert not parses("https://api.github.com/search?q=test")
        assert not parses("https://example.com/api?page=1&limit=10")

    def test_partial_segment_wildcards(self):
        assert parses("https://cdn.example.com/v*.zip")
        assert parses("https://cdn.example.com/release-*.tar.gz")
        assert parses("https://example.com/file*.json")

    def test_path_only_rules(self):
        assert parses("/repos/*/releases")
        assert parses("GET /api/v1/*")
        assert parses("POST /users/*/settings")
        assert parses("GET|HEAD|POST /api/*")

    def test_url_base_headers(self):
        assert parses("[https://api.github.com]")
        assert parses("[https://api.github.com/v1]")
        assert parses("[https://api.github.com/v1/repos]")
        assert parses("[https://example.com:8080/api]")

    def test_attributes_with_special_values(self):
        assert parses("github.com step=actions/setup-node")
        assert parses("github.com cgroup=@docker")
        assert parses('github.com arg="value with spaces"')
        assert parses("github.com arg=`wildcards * work`")

    def test_multiple_attributes(self):
        assert parses("github.com exe=/bin/sh step=build cgroup=@host")
        assert parses("registry.npmjs.org arg[0]=npm arg[1]=install")


class TestHypothesisFuzzing:
    """Property-based tests using hypothesis."""

    @given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz.-", min_size=1, max_size=50))
    @settings(max_examples=500)
    def test_random_hostname_like_strings(self, s):
        """Random hostname-like strings should either parse or not, but never crash."""
        # Just verify no exceptions are raised
        try:
            parse(s)
        except ParseError:
            pass

    @given(st.text(min_size=0, max_size=100))
    @settings(max_examples=500)
    def test_random_strings_dont_crash(self, s):
        """Random strings should either parse or raise ParseError, never crash."""
        try:
            parse(s)
        except ParseError:
            pass

    @given(st.sampled_from(VALID_RULES))
    def test_valid_rules_always_parse(self, rule):
        """All valid rules should parse."""
        assert parses(rule)

    @given(
        host=st.from_regex(r"[a-z][a-z0-9-]*[a-z0-9]", fullmatch=True),
        tld=st.from_regex(r"[a-z]{2,6}", fullmatch=True),
        port=st.integers(min_value=1, max_value=65535),
    )
    @settings(max_examples=200)
    def test_generated_hostname_with_port(self, host, tld, port):
        """Generated hostname:port combinations should parse."""
        assume(len(host) >= 1 and len(tld) >= 2)
        assume("--" not in host)  # No consecutive hyphens
        rule = f"{host}.{tld}:{port}"
        assert parses(rule), f"Should parse: {rule!r}"

    @given(
        a=st.integers(min_value=0, max_value=255),
        b=st.integers(min_value=0, max_value=255),
        c=st.integers(min_value=0, max_value=255),
        d=st.integers(min_value=0, max_value=255),
        mask=st.integers(min_value=0, max_value=32),
    )
    @settings(max_examples=200)
    def test_generated_cidr(self, a, b, c, d, mask):
        """Generated CIDR blocks should parse."""
        rule = f"{a}.{b}.{c}.{d}/{mask}"
        assert parses(rule), f"Should parse: {rule!r}"


class TestRoundTrip:
    """Test that parsed rules can be reconstructed."""

    # TODO: Implement serialization and test round-trip
    pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
