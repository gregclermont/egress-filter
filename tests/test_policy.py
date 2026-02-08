"""Test suite runner for policy parsing and matching.

Uses language-agnostic YAML test fixtures from tests/fixtures/.
"""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.policy import (
    DefaultContext,
    DNSIPCache,
    PolicyEnforcer,
    PolicyMatcher,
    ProcessInfo,
    parse_policy,
    rule_to_dict,
)

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
# Policy Flatten Tests
# =============================================================================

FLATTEN_FIXTURE = load_fixture("policy_flatten")


def flatten_test_ids():
    """Generate test IDs for flatten tests."""
    return [test["name"] for test in FLATTEN_FIXTURE["tests"]]


@pytest.mark.parametrize(
    "test_case",
    FLATTEN_FIXTURE["tests"],
    ids=flatten_test_ids(),
)
def test_policy_flatten(test_case):
    """Test policy flattening against expected rules."""
    policy = test_case["policy"]
    expected_rules = test_case["rules"]

    # Parse the policy
    rules = parse_policy(policy)

    # Convert to dict format for comparison
    actual_rules = [rule_to_dict(rule) for rule in rules]

    # Compare
    assert len(actual_rules) == len(expected_rules), (
        f"Rule count mismatch: got {len(actual_rules)}, expected {len(expected_rules)}\n"
        f"Actual: {actual_rules}\n"
        f"Expected: {expected_rules}"
    )

    for i, (actual, expected) in enumerate(zip(actual_rules, expected_rules)):
        # Compare each field
        assert actual["type"] == expected["type"], (
            f"Rule {i}: type mismatch: got {actual['type']}, expected {expected['type']}"
        )
        assert actual["target"] == expected["target"], (
            f"Rule {i}: target mismatch: got {actual['target']}, expected {expected['target']}"
        )
        assert actual["port"] == expected["port"], (
            f"Rule {i}: port mismatch: got {actual['port']}, expected {expected['port']}"
        )
        assert actual["protocol"] == expected["protocol"], (
            f"Rule {i}: protocol mismatch: got {actual['protocol']}, expected {expected['protocol']}"
        )
        assert actual["methods"] == expected["methods"], (
            f"Rule {i}: methods mismatch: got {actual['methods']}, expected {expected['methods']}"
        )
        assert actual["url_base"] == expected["url_base"], (
            f"Rule {i}: url_base mismatch: got {actual['url_base']}, expected {expected['url_base']}"
        )
        assert actual["attrs"] == expected["attrs"], (
            f"Rule {i}: attrs mismatch: got {actual['attrs']}, expected {expected['attrs']}"
        )
        if "passthrough" in expected:
            assert actual.get("passthrough", False) == expected["passthrough"], (
                f"Rule {i}: passthrough mismatch: got {actual.get('passthrough', False)}, expected {expected['passthrough']}"
            )


# =============================================================================
# DefaultContext Tests
# =============================================================================

DEFAULT_CONTEXT_FIXTURE = load_fixture("policy_default_context")


def default_context_test_ids():
    """Generate test IDs for default context tests."""
    return [test["name"] for test in DEFAULT_CONTEXT_FIXTURE["tests"]]


def build_default_context(defaults_dict: dict) -> DefaultContext:
    """Build a DefaultContext from a fixture dict."""
    kwargs = {}
    if "port" in defaults_dict:
        kwargs["port"] = defaults_dict["port"]
    if "protocol" in defaults_dict:
        kwargs["protocol"] = defaults_dict["protocol"]
    if "methods" in defaults_dict:
        kwargs["methods"] = defaults_dict["methods"]
    if "attrs" in defaults_dict:
        kwargs["attrs"] = defaults_dict["attrs"]
    return DefaultContext(**kwargs)


@pytest.mark.parametrize(
    "test_case",
    DEFAULT_CONTEXT_FIXTURE["tests"],
    ids=default_context_test_ids(),
)
def test_default_context(test_case):
    """Test policy parsing with custom DefaultContext."""
    defaults_dict = test_case.get("defaults", {})
    defaults = build_default_context(defaults_dict) if defaults_dict else None
    policy = test_case["policy"]
    expected_rules = test_case["rules"]

    # Parse the policy with custom defaults
    rules = parse_policy(policy, defaults=defaults)

    # Convert to dict format for comparison
    actual_rules = [rule_to_dict(rule) for rule in rules]

    # Compare
    assert len(actual_rules) == len(expected_rules), (
        f"Rule count mismatch: got {len(actual_rules)}, expected {len(expected_rules)}\n"
        f"Actual: {actual_rules}\n"
        f"Expected: {expected_rules}"
    )

    for i, (actual, expected) in enumerate(zip(actual_rules, expected_rules)):
        assert actual["type"] == expected["type"], (
            f"Rule {i}: type mismatch: got {actual['type']}, expected {expected['type']}"
        )
        assert actual["target"] == expected["target"], (
            f"Rule {i}: target mismatch: got {actual['target']}, expected {expected['target']}"
        )
        assert actual["port"] == expected["port"], (
            f"Rule {i}: port mismatch: got {actual['port']}, expected {expected['port']}"
        )
        assert actual["protocol"] == expected["protocol"], (
            f"Rule {i}: protocol mismatch: got {actual['protocol']}, expected {expected['protocol']}"
        )
        assert actual["methods"] == expected["methods"], (
            f"Rule {i}: methods mismatch: got {actual['methods']}, expected {expected['methods']}"
        )
        assert actual["url_base"] == expected["url_base"], (
            f"Rule {i}: url_base mismatch: got {actual['url_base']}, expected {expected['url_base']}"
        )
        assert actual["attrs"] == expected["attrs"], (
            f"Rule {i}: attrs mismatch: got {actual['attrs']}, expected {expected['attrs']}"
        )


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
# Policy Enforcer End-to-End Tests
# =============================================================================

ENFORCER_FIXTURE = load_fixture("policy_enforcer")


def generate_enforcer_test_cases():
    """Generate individual test cases from the enforcer fixture.

    Each test scenario may have multiple checks. We generate a test case
    for each check, but process the entire scenario (including dns_response
    events) to maintain state.
    """
    cases = []
    for test in ENFORCER_FIXTURE["tests"]:
        test_name = test["name"]
        policy = test["policy"]
        dns_cache = test.get("dns_cache", [])
        audit_mode = test.get("audit_mode", False)
        checks = test["checks"]

        # Group checks into scenario
        cases.append(
            {
                "name": test_name,
                "policy": policy,
                "dns_cache": dns_cache,
                "audit_mode": audit_mode,
                "checks": checks,
            }
        )
    return cases


ENFORCER_TEST_CASES = generate_enforcer_test_cases()


@pytest.mark.parametrize(
    "scenario",
    ENFORCER_TEST_CASES,
    ids=[c["name"] for c in ENFORCER_TEST_CASES],
)
def test_policy_enforcer(scenario):
    """Test enforcer scenarios from YAML fixtures."""
    # Set up enforcer
    matcher = PolicyMatcher(scenario["policy"])
    dns_cache = DNSIPCache()

    # Pre-populate DNS cache
    for entry in scenario["dns_cache"]:
        dns_cache.add_many(
            entry["ips"],
            entry["hostname"],
            entry.get("ttl", 300),
        )

    enforcer = PolicyEnforcer(matcher, dns_cache, audit_mode=scenario["audit_mode"])

    # Process each check in sequence
    for i, check in enumerate(scenario["checks"]):
        check_type = check["type"]

        # dns_response is not a check - it updates the cache
        if check_type == "dns_response":
            enforcer.record_dns_response(
                query_name=check["query_name"],
                ips=check["ips"],
                ttl=check.get("ttl", 300),
            )
            continue

        # Build process info if provided
        proc = None
        if "proc" in check:
            proc = ProcessInfo(
                exe=check["proc"].get("exe"),
                cmdline=check["proc"].get("cmdline"),
                cgroup=check["proc"].get("cgroup"),
                step=check["proc"].get("step"),
            )

        # Run the appropriate check
        if check_type == "https":
            decision = enforcer.check_https(
                dst_ip=check["dst_ip"],
                dst_port=check["dst_port"],
                sni=check.get("sni"),
                proc=proc,
                can_mitm=check.get("can_mitm", False),
            )
        elif check_type == "http":
            decision = enforcer.check_http(
                dst_ip=check["dst_ip"],
                dst_port=check["dst_port"],
                url=check["url"],
                method=check["method"],
                proc=proc,
            )
        elif check_type == "tcp":
            decision = enforcer.check_tcp(
                dst_ip=check["dst_ip"],
                dst_port=check["dst_port"],
                proc=proc,
            )
        elif check_type == "dns":
            decision = enforcer.check_dns(
                dst_ip=check["dst_ip"],
                dst_port=check["dst_port"],
                query_name=check["query_name"],
                proc=proc,
            )
        elif check_type == "udp":
            decision = enforcer.check_udp(
                dst_ip=check["dst_ip"],
                dst_port=check["dst_port"],
                proc=proc,
            )
        else:
            pytest.fail(f"Unknown check type: {check_type}")

        # Verify verdict
        expected_verdict = check["verdict"]
        actual_verdict = "allow" if decision.allowed else "block"

        assert actual_verdict == expected_verdict, (
            f"Scenario '{scenario['name']}', check {i} ({check_type}):\n"
            f"Check: {check}\n"
            f"Expected: {expected_verdict}, Got: {actual_verdict}\n"
            f"Reason: {decision.reason}"
        )

        # Check passthrough flag if specified in fixture
        if "passthrough" in check:
            expected_passthrough = check["passthrough"]
            assert decision.passthrough == expected_passthrough, (
                f"Scenario '{scenario['name']}', check {i} ({check_type}):\n"
                f"Check: {check}\n"
                f"Expected passthrough: {expected_passthrough}, Got: {decision.passthrough}"
            )


# =============================================================================
# Placeholder Substitution Tests
# =============================================================================


class TestParseGithubRepository:
    """Tests for parse_github_repository function."""

    def test_basic_owner_repo(self):
        from proxy.policy import parse_github_repository

        owner, repo = parse_github_repository("anthropics/egress-filter")
        assert owner == "anthropics"
        assert repo == "egress-filter"

    def test_none_input(self):
        from proxy.policy import parse_github_repository

        owner, repo = parse_github_repository(None)
        assert owner is None
        assert repo is None

    def test_empty_string(self):
        from proxy.policy import parse_github_repository

        owner, repo = parse_github_repository("")
        assert owner is None
        assert repo is None

    def test_no_slash(self):
        from proxy.policy import parse_github_repository

        owner, repo = parse_github_repository("invalid")
        assert owner is None
        assert repo is None

    def test_multiple_slashes(self):
        from proxy.policy import parse_github_repository

        # Split on first slash only - repo can contain slashes
        owner, repo = parse_github_repository("owner/repo/extra")
        assert owner == "owner"
        assert repo == "repo/extra"

    def test_org_with_hyphen(self):
        from proxy.policy import parse_github_repository

        owner, repo = parse_github_repository("my-org/my-repo")
        assert owner == "my-org"
        assert repo == "my-repo"


class TestSubstitutePlaceholders:
    """Tests for substitute_placeholders function."""

    def test_basic_substitution(self):
        from proxy.policy import substitute_placeholders

        result = substitute_placeholders(
            "https://github.com/{owner}/{repo}/info/refs",
            owner="anthropics",
            repo="egress-filter",
        )
        assert result == "https://github.com/anthropics/egress-filter/info/refs"

    def test_no_substitution_when_none(self):
        from proxy.policy import substitute_placeholders

        result = substitute_placeholders(
            "https://github.com/{owner}/{repo}",
            owner=None,
            repo=None,
        )
        assert result == "https://github.com/{owner}/{repo}"

    def test_partial_substitution_owner_only(self):
        from proxy.policy import substitute_placeholders

        result = substitute_placeholders(
            "https://github.com/{owner}/{repo}",
            owner="anthropics",
            repo=None,
        )
        assert result == "https://github.com/anthropics/{repo}"

    def test_partial_substitution_repo_only(self):
        from proxy.policy import substitute_placeholders

        result = substitute_placeholders(
            "https://github.com/{owner}/{repo}",
            owner=None,
            repo="egress-filter",
        )
        assert result == "https://github.com/{owner}/egress-filter"

    def test_multiple_occurrences(self):
        from proxy.policy import substitute_placeholders

        result = substitute_placeholders(
            "{owner}/{owner}/{repo}/{repo}",
            owner="a",
            repo="b",
        )
        assert result == "a/a/b/b"

    def test_no_placeholders(self):
        from proxy.policy import substitute_placeholders

        result = substitute_placeholders(
            "https://github.com/fixed/path",
            owner="unused",
            repo="unused",
        )
        assert result == "https://github.com/fixed/path"

    def test_in_policy_context(self):
        from proxy.policy import substitute_placeholders

        policy = """
[exe=/usr/lib/git-core/git-remote-http]
GET  https://github.com/{owner}/{repo}/info/refs
POST https://github.com/{owner}/{repo}/git-upload-pack
"""
        result = substitute_placeholders(policy, owner="anthropics", repo="egress-filter")
        assert "https://github.com/anthropics/egress-filter/info/refs" in result
        assert "https://github.com/anthropics/egress-filter/git-upload-pack" in result
        assert "{owner}" not in result
        assert "{repo}" not in result


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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
