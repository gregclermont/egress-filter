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


# =============================================================================
# validate_policy Tests
# =============================================================================

from proxy.policy.parser import (
    _check_passthrough_url_overlap,
    _extract_url_rule_hostname,
    flatten_policy,
    validate_policy,
)


class TestValidatePolicy:
    """Tests for validate_policy function."""

    def test_valid_policy_no_errors(self):
        errors = validate_policy("github.com\n*.github.com")
        assert errors == []

    def test_invalid_line_returns_error(self):
        errors = validate_policy("not a valid rule!!!")
        assert len(errors) == 1
        line_num, text, msg = errors[0]
        assert line_num == 1
        assert text == "not a valid rule!!!"

    def test_mixed_valid_invalid(self):
        policy = "github.com\n!!invalid!!\nexample.com"
        errors = validate_policy(policy)
        assert len(errors) == 1
        assert errors[0][0] == 2  # line 2

    def test_skips_comments_and_blanks(self):
        policy = "# comment\n\ngithub.com\n  # another comment"
        errors = validate_policy(policy)
        assert errors == []

    def test_comment_after_valid_rule_first_line(self):
        """Policy starting with a comment line followed by a valid rule."""
        policy = "# comment\ngithub.com"
        errors = validate_policy(policy)
        assert errors == []

    def test_passthrough_on_url_rule_warns(self):
        """passthrough on a URL rule type generates a warning."""
        policy = "[passthrough]\nhttps://example.com/api/*"
        errors = validate_policy(policy)
        assert len(errors) == 1
        assert "passthrough" in errors[0][2].lower()

    def test_passthrough_overlap_with_url_rule(self):
        """Passthrough on a hostname that also has URL rules warns."""
        policy = "github.com\nGET https://github.com/api/*\ngithub.com passthrough"
        errors = validate_policy(policy)
        assert any("passthrough" in e[2] and "overlap" in e[2] for e in errors)

    def test_passthrough_no_overlap_no_warning(self):
        """Passthrough on a hostname without URL rules is fine."""
        policy = "github.com\ngithub.com passthrough"
        errors = validate_policy(policy)
        assert errors == []

    def test_multiple_invalid_lines(self):
        policy = "!!invalid1!!\n!!invalid2!!\n!!invalid3!!"
        errors = validate_policy(policy)
        assert len(errors) == 3
        assert errors[0][0] == 1
        assert errors[1][0] == 2
        assert errors[2][0] == 3

    def test_comment_then_invalid_line(self):
        policy = "# comment\n!!invalid!!"
        errors = validate_policy(policy)
        assert len(errors) == 1

    def test_blank_then_invalid_line(self):
        policy = "\n!!invalid!!"
        errors = validate_policy(policy)
        assert len(errors) == 1

    def test_error_message_contains_parse_info(self):
        errors = validate_policy("!!invalid!!")
        assert len(errors) == 1
        _, _, msg = errors[0]
        assert msg != "None"
        assert len(msg) > 0


class TestExtractUrlRuleHostname:
    """Tests for _extract_url_rule_hostname."""

    def test_url_rule(self):
        from proxy.policy.types import Rule
        rule = Rule(type="url", target="https://example.com/api/*",
                    port=[443], protocol="tcp", methods=["GET"], url_base=None, attrs={})
        assert _extract_url_rule_hostname(rule) == "example.com"

    def test_path_rule_with_url_base(self):
        from proxy.policy.types import Rule
        rule = Rule(type="path", target="/api/*",
                    port=[443], protocol="tcp", methods=["GET"],
                    url_base="https://api.github.com", attrs={})
        assert _extract_url_rule_hostname(rule) == "api.github.com"

    def test_path_rule_without_url_base(self):
        from proxy.policy.types import Rule
        rule = Rule(type="path", target="/api/*",
                    port=[443], protocol="tcp", methods=["GET"],
                    url_base=None, attrs={})
        assert _extract_url_rule_hostname(rule) is None

    def test_host_rule_returns_none(self):
        from proxy.policy.types import Rule
        rule = Rule(type="host", target="example.com",
                    port=[443], protocol="tcp", methods=None, url_base=None, attrs={})
        assert _extract_url_rule_hostname(rule) is None


class TestCheckPassthroughUrlOverlap:
    """Tests for _check_passthrough_url_overlap."""

    def test_no_passthrough_rules(self):
        rules = parse_policy("github.com\nGET https://github.com/api/*")
        warnings = _check_passthrough_url_overlap(rules)
        assert warnings == []

    def test_no_url_rules(self):
        rules = parse_policy("github.com\ngithub.com passthrough")
        warnings = _check_passthrough_url_overlap(rules)
        assert warnings == []

    def test_overlap_detected(self):
        rules = parse_policy("github.com\nGET https://github.com/api/*\ngithub.com passthrough")
        warnings = _check_passthrough_url_overlap(rules)
        assert len(warnings) == 1
        assert warnings[0][0] == 0  # line_num is 0 for cross-rule warnings
        assert "overlap" in warnings[0][2]

    def test_no_overlap_different_host(self):
        rules = parse_policy("example.com\nGET https://github.com/api/*\nexample.com passthrough")
        warnings = _check_passthrough_url_overlap(rules)
        assert warnings == []

    def test_wildcard_passthrough_overlaps_url(self):
        rules = parse_policy("*.github.com\nGET https://api.github.com/repos/*\n*.github.com passthrough")
        warnings = _check_passthrough_url_overlap(rules)
        assert len(warnings) == 1

    def test_passthrough_overlaps_path_rule(self):
        rules = parse_policy(
            "[https://api.github.com]\n"
            "GET /repos/*\n"
            "[]\n"
            "api.github.com\n"
            "api.github.com passthrough"
        )
        warnings = _check_passthrough_url_overlap(rules)
        assert len(warnings) == 1


class TestFlattenPolicy:
    """Tests for flatten_policy convenience function."""

    def test_basic_flatten(self):
        result = list(flatten_policy("github.com"))
        assert len(result) == 1
        assert result[0]["type"] == "host"
        assert result[0]["target"] == "github.com"

    def test_multiple_rules(self):
        result = list(flatten_policy("github.com\n*.github.com"))
        assert len(result) == 2
        assert result[0]["type"] == "host"
        assert result[1]["type"] == "wildcard_host"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
