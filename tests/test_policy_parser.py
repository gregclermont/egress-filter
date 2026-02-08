"""Tests for policy parsing: flattening, DefaultContext, placeholders, rule_to_dict.

Uses YAML test fixtures from tests/fixtures/.
"""

import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.policy import (
    DefaultContext,
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


# =============================================================================
# rule_to_dict Tests
# =============================================================================


class TestRuleToDict:
    """Tests for rule_to_dict serialization."""

    def test_dump_simple_rules(self):
        """Dump simple host and IP rules."""
        policy = """
        github.com
        *.github.com
        8.8.8.8:53/udp
        """
        rules = parse_policy(policy)
        dumped = [rule_to_dict(r) for r in rules]

        assert len(dumped) == 3

        # First rule: exact host
        assert dumped[0]["type"] == "host"
        assert dumped[0]["target"] == "github.com"
        assert dumped[0]["port"] == [443]
        assert dumped[0]["protocol"] == "tcp"

        # Second rule: wildcard host
        assert dumped[1]["type"] == "wildcard_host"
        assert dumped[1]["target"] == "*.github.com"

        # Third rule: IP with UDP
        assert dumped[2]["type"] == "ip"
        assert dumped[2]["target"] == "8.8.8.8"
        assert dumped[2]["port"] == [53]
        assert dumped[2]["protocol"] == "udp"

    def test_dump_url_rules(self):
        """Dump URL and path rules."""
        policy = """
        [https://api.github.com]
        GET /repos/*/releases
        POST /repos/*/issues
        """
        rules = parse_policy(policy)
        dumped = [rule_to_dict(r) for r in rules]

        assert len(dumped) == 2

        # GET path rule
        assert dumped[0]["type"] == "path"
        assert dumped[0]["target"] == "/repos/*/releases"
        assert dumped[0]["methods"] == ["GET"]
        assert dumped[0]["url_base"] == "https://api.github.com"

        # POST path rule
        assert dumped[1]["type"] == "path"
        assert dumped[1]["target"] == "/repos/*/issues"
        assert dumped[1]["methods"] == ["POST"]

    def test_dump_rules_with_attrs(self):
        """Dump rules with attributes."""
        policy = """
        github.com exe=/usr/bin/git
        """
        rules = parse_policy(policy)
        dumped = [rule_to_dict(r) for r in rules]

        assert len(dumped) == 1
        assert dumped[0]["attrs"] == {"exe": "/usr/bin/git"}

    def test_dump_is_json_serializable(self):
        """Dumped rules can be serialized to JSON."""
        policy = """
        github.com
        [https://api.github.com]
        GET /repos/*
        """
        rules = parse_policy(policy)
        dumped = [rule_to_dict(r) for r in rules]

        # Should not raise
        json_str = json.dumps(dumped)
        parsed = json.loads(json_str)

        assert len(parsed) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
