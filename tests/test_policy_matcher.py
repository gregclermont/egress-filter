"""Tests for policy matching: verdict computation and attribute matching.

Uses YAML test fixtures from tests/fixtures/.
"""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.policy import PolicyMatcher

# =============================================================================
# Load test fixtures
# =============================================================================

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    """Load a YAML test fixture."""
    path = FIXTURES_DIR / f"{name}.yaml"
    with open(path) as f:
        return yaml.safe_load(f)


# =============================================================================
# Policy Match Tests
# =============================================================================

MATCH_FIXTURE = load_fixture("policy_match")


def generate_match_test_cases():
    """Generate individual test cases from the match fixture."""
    cases = []
    for test in MATCH_FIXTURE["tests"]:
        policy = test["policy"]
        for i, conn in enumerate(test["connections"]):
            case_id = f"{test['name']} - connection {i}"
            cases.append((case_id, policy, conn["event"], conn["verdict"]))
    return cases


MATCH_TEST_CASES = generate_match_test_cases()


@pytest.mark.parametrize(
    "case_id,policy,event,expected_verdict",
    MATCH_TEST_CASES,
    ids=[c[0] for c in MATCH_TEST_CASES],
)
def test_policy_match(case_id, policy, event, expected_verdict):
    """Test connection matching against policy."""
    matcher = PolicyMatcher(policy)
    actual_verdict = matcher.verdict(event)

    assert actual_verdict == expected_verdict, (
        f"Verdict mismatch for '{case_id}':\n"
        f"Policy:\n{policy}\n"
        f"Event: {event}\n"
        f"Expected: {expected_verdict}, Got: {actual_verdict}"
    )


# =============================================================================
# Attribute Matching
# =============================================================================


class TestUnknownAttributes:
    """Defense-in-depth: match_attrs rejects unknown attribute keys."""

    def test_unknown_key_returns_false(self):
        from proxy.policy.matcher import match_attrs, ConnectionEvent
        from proxy.policy.types import Rule

        rule = Rule(
            type="host",
            target="github.com",
            port=[443],
            protocol="tcp",
            methods=None,
            url_base=None,
            attrs={"typo": "foo"},
        )
        event = ConnectionEvent(
            type="https",
            dst_ip="140.82.121.4",
            dst_port=443,
            host="github.com",
        )
        assert not match_attrs(rule, event)


# =============================================================================
# Unit tests for helper functions (found via mutation testing)
# =============================================================================

from proxy.policy.matcher import (
    ConnectionEvent,
    cidr_contains,
    match_attrs,
    match_attr_value,
    match_dns_name_against_rule,
    match_hostname,
    match_method,
    match_port,
    match_protocol,
    match_rule,
    match_rule_hostname_only,
    match_url_path,
)
from proxy.policy.types import AttrValue, Rule


def _rule(**overrides):
    """Create a Rule with sensible defaults."""
    defaults = dict(
        type="host",
        target="example.com",
        port=[443],
        protocol="tcp",
        methods=None,
        url_base=None,
        attrs={},
    )
    defaults.update(overrides)
    return Rule(**defaults)


def _event(**overrides):
    """Create a ConnectionEvent with sensible defaults."""
    defaults = dict(type="https", dst_ip="93.184.216.34", dst_port=443)
    defaults.update(overrides)
    return ConnectionEvent(**defaults)


class TestCidrContains:
    """Edge cases for CIDR mask calculation."""

    def test_off_by_one_in_mask_shift(self):
        """Mutant: (32 - prefix_len) changed to (33 - prefix_len)."""
        # /31 contains exactly two IPs: .0 and .1
        assert cidr_contains("10.0.0.0/31", "10.0.0.0")
        assert cidr_contains("10.0.0.0/31", "10.0.0.1")
        assert not cidr_contains("10.0.0.0/31", "10.0.0.2")


class TestMatchHostname:
    """Edge cases in hostname matching."""

    def test_non_wildcard_label_pattern_no_prefix(self):
        """Wildcard rule without *. prefix and no glob chars: exact first label."""
        assert match_hostname("foo.example.com", "foo.example.com", is_wildcard=True)
        assert not match_hostname("foo.example.com", "bar.example.com", is_wildcard=True)


class TestMatchUrlPath:
    """Edge cases in URL path matching."""

    def test_root_path_normalization(self):
        """Root '/' should not be stripped."""
        assert match_url_path("/", "/")
        assert not match_url_path("/", "/foo")

    def test_trailing_slash_stripped(self):
        assert match_url_path("/foo/", "/foo")
        assert match_url_path("/foo", "/foo/")

    def test_trailing_wildcard_exact_prefix_length(self):
        """Trailing wildcard: actual path with same segment count as prefix."""
        assert match_url_path("/a/b/*", "/a/b/c")
        assert match_url_path("/a/b/*", "/a/b")
        assert not match_url_path("/a/b/*", "/a")

    def test_trailing_wildcard_too_few_segments(self):
        assert not match_url_path("/api/v1/*", "/api")

    def test_segment_bounds_check(self):
        """Pattern has more segments than actual path."""
        assert not match_url_path("/a/b/c", "/a/b")

    def test_star_segment_matches_one(self):
        """A bare '*' segment matches exactly one path segment."""
        assert match_url_path("/api/*/items", "/api/v1/items")
        assert not match_url_path("/api/*/items", "/api/v1/v2/items")


class TestMatchPort:
    def test_non_list_non_star_returns_false(self):
        """Unexpected port type should return False (defense in depth)."""
        assert not match_port(443, 443)


class TestMatchProtocol:
    def test_udp_matches_dns(self):
        assert match_protocol("udp", "dns")
        assert match_protocol("udp", "udp")

    def test_unknown_protocol_returns_false(self):
        assert not match_protocol("icmp", "http")
        assert not match_protocol("", "https")


class TestMatchMethod:
    def test_none_methods_always_matches(self):
        """Non-HTTP rule (methods=None) matches any method."""
        assert match_method(None, "GET")
        assert match_method(None, "POST")
        assert match_method(None, None)


class TestMatchAttrValue:
    def test_literal_attr_exact_match(self):
        av = AttrValue(value="exact-val", literal=True)
        assert match_attr_value(av, "exact-val")
        assert not match_attr_value(av, "other-val")

    def test_pattern_attr_wildcard_match(self):
        av = AttrValue(value="/usr/bin/*", literal=False)
        assert match_attr_value(av, "/usr/bin/python3")
        assert not match_attr_value(av, "/usr/local/bin/python3")


class TestMatchAttrsMultiple:
    """Test match_attrs with multiple attributes (catches continue/break mutants)."""

    def test_multiple_attrs_all_must_match(self):
        rule = _rule(attrs={"exe": "/usr/bin/curl", "step": "download"})
        assert match_attrs(rule, _event(host="x.com", exe="/usr/bin/curl", step="download"))
        assert not match_attrs(rule, _event(host="x.com", exe="/usr/bin/curl", step="upload"))
        assert not match_attrs(rule, _event(host="x.com", exe="/usr/bin/wget", step="download"))

    def test_exe_and_cgroup_both_checked(self):
        rule = _rule(attrs={"exe": "/usr/bin/curl", "cgroup": "@docker"})
        event = _event(host="x.com", exe="/usr/bin/curl", cgroup="/user.slice/user.service")
        assert not match_attrs(rule, event)

    def test_step_and_action_both_checked(self):
        rule = _rule(attrs={"step": "build", "action": "actions/checkout"})
        assert match_attrs(rule, _event(host="x.com", step="build", action="actions/checkout"))
        assert not match_attrs(rule, _event(host="x.com", step="build", action="actions/setup-node"))

    def test_image_and_exe_both_checked(self):
        rule = _rule(attrs={"image": "node:18*", "exe": "/usr/bin/npm"})
        assert match_attrs(rule, _event(host="x.com", image="node:18-alpine", exe="/usr/bin/npm"))
        assert not match_attrs(rule, _event(host="x.com", image="node:18-alpine", exe="/usr/bin/yarn"))

    def test_arg_with_no_cmdline_returns_false(self):
        rule = _rule(attrs={"arg": "secret"})
        assert not match_attrs(rule, _event(host="x.com", cmdline=None))

    def test_cgroup_none_returns_false(self):
        rule = _rule(attrs={"cgroup": "@docker"})
        assert not match_attrs(rule, _event(host="x.com", cgroup=None))


class TestMatchAttrsContinueBreak:
    """Ensure each attr branch continues to next attr (catches continue→break)."""

    def test_arg_then_exe_both_checked(self):
        """Mutant: continue→break after arg match skips exe check."""
        rule = _rule(attrs={"arg": "--verbose", "exe": "/usr/bin/curl"})
        # arg matches but exe doesn't
        assert not match_attrs(rule, _event(
            host="x.com", cmdline=["wget", "--verbose"], exe="/usr/bin/wget",
        ))

    def test_action_then_image_both_checked(self):
        """Mutant: continue→break after action match skips image check."""
        rule = _rule(attrs={"action": "actions/checkout", "image": "node:18*"})
        # action matches but image doesn't
        assert not match_attrs(rule, _event(
            host="x.com", action="actions/checkout", image="python:3.12",
        ))

    def test_cgroup_then_image_both_checked(self):
        """Mutant: continue→break after cgroup match skips image check."""
        rule = _rule(attrs={"cgroup": "@docker", "image": "node:18*"})
        # cgroup matches but image doesn't
        assert not match_attrs(rule, _event(
            host="x.com", cgroup="/docker/abc123", image="python:3.12",
        ))

    def test_indexed_arg_then_exe_both_checked(self):
        """Mutant: continue→break after arg[N] match skips exe check."""
        rule = _rule(attrs={"arg[0]": "curl", "exe": "/usr/bin/curl"})
        # arg[0] matches but exe doesn't
        assert not match_attrs(rule, _event(
            host="x.com", cmdline=["curl", "http://x.com"], exe="/usr/bin/wget",
        ))


class TestMatchDnsNameAgainstRule:
    """DNS name matching against URL/path rule types."""

    def test_dns_host_no_match(self):
        """Mutant: return False → return True when dns_host doesn't match."""
        rule = _rule(type="dns_host", target="example.com")
        event = _event(type="dns", dst_ip="1.1.1.1", dst_port=53, name="other.com")
        assert not match_dns_name_against_rule(rule, event.name, event)

    def test_host_rule_no_match(self):
        """Mutant: return False → return True when host rule doesn't match DNS name."""
        rule = _rule(type="host", target="example.com")
        event = _event(type="dns", dst_ip="1.1.1.1", dst_port=53, name="other.com")
        assert not match_dns_name_against_rule(rule, event.name, event)

    def test_url_rule_dns_match(self):
        rule = _rule(type="url", target="https://registry.npmjs.org/express/*", methods=["GET"])
        event = _event(type="dns", dst_ip="1.1.1.1", dst_port=53, name="registry.npmjs.org")
        assert match_dns_name_against_rule(rule, event.name, event)

    def test_url_rule_dns_no_match(self):
        rule = _rule(type="url", target="https://registry.npmjs.org/express/*", methods=["GET"])
        event = _event(type="dns", dst_ip="1.1.1.1", dst_port=53, name="pypi.org")
        assert not match_dns_name_against_rule(rule, event.name, event)

    def test_path_rule_dns_match(self):
        rule = _rule(type="path", target="/api/*", url_base="https://api.github.com", methods=["GET"])
        event = _event(type="dns", dst_ip="1.1.1.1", dst_port=53, name="api.github.com")
        assert match_dns_name_against_rule(rule, event.name, event)

    def test_path_rule_dns_no_url_base(self):
        rule = _rule(type="path", target="/api/*", url_base=None, methods=["GET"])
        event = _event(type="dns", dst_ip="1.1.1.1", dst_port=53, name="api.github.com")
        assert not match_dns_name_against_rule(rule, event.name, event)

    def test_dns_wildcard_host_no_match(self):
        rule = _rule(type="dns_wildcard_host", target="*.example.com")
        event = _event(type="dns", dst_ip="1.1.1.1", dst_port=53, name="other.org")
        assert not match_dns_name_against_rule(rule, event.name, event)

    def test_ip_rule_does_not_match_dns(self):
        rule = _rule(type="ip", target="1.2.3.4")
        event = _event(type="dns", dst_ip="1.1.1.1", dst_port=53, name="example.com")
        assert not match_dns_name_against_rule(rule, event.name, event)

    def test_url_rule_dns_case_insensitive(self):
        rule = _rule(type="url", target="https://Registry.NPMjs.Org/express/*", methods=["GET"])
        event = _event(type="dns", dst_ip="1.1.1.1", dst_port=53, name="registry.npmjs.org")
        assert match_dns_name_against_rule(rule, event.name, event)

    def test_url_rule_no_hostname_blocks_dns(self):
        """Mutant: return False → return True when URL has no hostname."""
        rule = _rule(type="url", target="https:///some/path", methods=["GET"])
        event = _event(type="dns", dst_ip="1.1.1.1", dst_port=53, name="anything.com")
        assert not match_dns_name_against_rule(rule, event.name, event)


class TestMatchRuleUrlPath:
    """match_rule for URL and path rule types."""

    def test_url_rule_no_url_blocks(self):
        rule = _rule(type="url", target="https://example.com/api/*", methods=["GET"])
        event = _event(type="https", host="example.com")
        assert not match_rule(rule, event)

    def test_path_rule_no_url_base_blocks(self):
        rule = _rule(type="path", target="/api/*", url_base=None, methods=["GET"])
        event = _event(type="http", url="https://example.com/api/data", method="GET")
        assert not match_rule(rule, event)

    def test_path_rule_scheme_mismatch_blocks(self):
        rule = _rule(type="path", target="/api/*", url_base="https://example.com", methods=["GET"])
        event = _event(type="http", url="http://example.com/api/data", method="GET")
        assert not match_rule(rule, event)

    def test_path_rule_host_mismatch_blocks(self):
        rule = _rule(type="path", target="/api/*", url_base="https://api.example.com", methods=["GET"])
        event = _event(type="http", url="https://other.example.com/api/data", method="GET")
        assert not match_rule(rule, event)


class TestMatchRuleUrlEdgeCases:
    """URL and path rule edge cases in match_rule (found via mutation testing)."""

    def test_url_rule_hostname_none_does_not_crash(self):
        """Mutant: 'and' → 'or' in hostname null check.
        URL like 'https:///path' has no hostname — and→or would crash."""
        rule = _rule(type="url", target="https:///path", port=[443], methods=["GET"])
        event = _event(type="http", url="https://example.com/path", method="GET")
        # When rule has no hostname, hostname check is skipped (and semantics).
        # With 'or' mutant, it would crash on None.lower().
        match_rule(rule, event)  # should not raise

    def test_url_rule_scheme_mismatch(self):
        """URL rule scheme must match event scheme."""
        rule = _rule(type="url", target="https://example.com/api", port=[80, 443], methods=["GET"])
        event = _event(type="http", dst_port=80, url="http://example.com/api", method="GET")
        assert not match_rule(rule, event)

    def test_path_rule_base_path_concat(self):
        """Path rule: base path + rule path concatenation."""
        rule = _rule(
            type="path", target="/items/*",
            url_base="https://example.com/api/v1",
            port=[443], methods=["GET"],
        )
        event = _event(type="http", url="https://example.com/api/v1/items/123", method="GET")
        assert match_rule(rule, event)

    def test_path_rule_base_path_mismatch(self):
        """Path rule: hostname mismatch in base blocks."""
        rule = _rule(
            type="path", target="/items/*",
            url_base="https://api.example.com/v1",
            port=[443], methods=["GET"],
        )
        event = _event(type="http", url="https://wrong.example.com/v1/items/123", method="GET")
        assert not match_rule(rule, event)

    def test_wildcard_host_no_hostname_blocks(self):
        """Wildcard host rule blocks when event has no hostname."""
        rule = _rule(type="wildcard_host", target="*.example.com")
        event = _event(type="tcp", dst_ip="1.2.3.4", dst_port=443)
        assert not match_rule(rule, event)

    def test_url_rule_no_path_defaults_to_root(self):
        """Mutant: rule_parsed.path or '/' → or 'XX/XX'."""
        rule = _rule(type="url", target="https://example.com", port=[443], methods=["GET"])
        event = _event(type="http", url="https://example.com/", host="example.com", method="GET")
        assert match_rule(rule, event)

    def test_url_rule_event_no_path_defaults_to_root(self):
        """Mutant: event_parsed.path or '/' → or 'XX/XX'."""
        rule = _rule(type="url", target="https://example.com/", port=[443], methods=["GET"])
        event = _event(type="http", url="https://example.com", host="example.com", method="GET")
        assert match_rule(rule, event)

    def test_path_rule_event_no_path_defaults_to_root(self):
        """Mutant: event_parsed.path or '/' → or 'XX/XX' in path branch."""
        rule = _rule(
            type="path", target="/",
            url_base="https://example.com",
            port=[443], methods=["GET"],
        )
        event = _event(type="http", url="https://example.com", host="example.com", method="GET")
        assert match_rule(rule, event)


class TestMatchRuleHostnameOnly:
    """match_rule_hostname_only (TLS pre-matching for URL/path rules)."""

    def test_url_rule_sni_match(self):
        rule = _rule(type="url", target="https://example.com/api/*", methods=["GET"])
        event = _event(type="https", host="example.com")
        assert match_rule_hostname_only(rule, event)

    def test_url_rule_sni_mismatch(self):
        rule = _rule(type="url", target="https://example.com/api/*", methods=["GET"])
        event = _event(type="https", host="other.com")
        assert not match_rule_hostname_only(rule, event)

    def test_host_rule_type_rejected(self):
        rule = _rule(type="host", target="example.com")
        event = _event(type="https", host="example.com")
        assert not match_rule_hostname_only(rule, event)

    def test_wrong_protocol_rejected(self):
        rule = _rule(type="url", target="https://example.com/*", methods=["GET"])
        event = _event(type="udp", host="example.com")
        assert not match_rule_hostname_only(rule, event)

    def test_wrong_port_rejected(self):
        rule = _rule(type="url", target="https://example.com/*", methods=["GET"])
        event = _event(type="https", dst_port=8443, host="example.com")
        assert not match_rule_hostname_only(rule, event)

    def test_no_hostname_in_event(self):
        rule = _rule(type="url", target="https://example.com/*", methods=["GET"])
        event = _event(type="https")
        assert not match_rule_hostname_only(rule, event)

    def test_path_rule_sni_match(self):
        rule = _rule(type="path", target="/api/*", url_base="https://api.github.com", methods=["GET"])
        event = _event(type="https", dst_ip="140.82.121.4", host="api.github.com")
        assert match_rule_hostname_only(rule, event)

    def test_path_rule_no_url_base(self):
        rule = _rule(type="path", target="/api/*", url_base=None, methods=["GET"])
        event = _event(type="https", host="example.com")
        assert not match_rule_hostname_only(rule, event)

    def test_url_rule_no_hostname_in_target(self):
        rule = _rule(type="url", target="/relative/path", methods=["GET"])
        event = _event(type="https", host="example.com")
        assert not match_rule_hostname_only(rule, event)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
