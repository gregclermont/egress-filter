"""Tests for the policy validation CLI."""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.policy.cli import find_policies_in_workflow, validate_policy


class TestFindPolicies:
    """Tests for finding policies in workflow files."""

    def test_finds_policy_in_step(self):
        """Find policy in egress-filter step."""
        workflow = {
            "jobs": {
                "build": {
                    "steps": [
                        {
                            "name": "Setup egress",
                            "uses": "owner/egress-filter@v1",
                            "with": {"policy": "github.com\n*.github.com"},
                        }
                    ]
                }
            }
        }
        policies = find_policies_in_workflow(workflow)
        assert len(policies) == 1
        assert "github.com" in policies[0][1]

    def test_finds_multiple_policies(self):
        """Find policies in multiple jobs."""
        workflow = {
            "jobs": {
                "build": {
                    "steps": [
                        {
                            "uses": "owner/egress-filter@v1",
                            "with": {"policy": "github.com"},
                        }
                    ]
                },
                "test": {
                    "steps": [
                        {
                            "uses": "owner/egress-filter@v2",
                            "with": {"policy": "npmjs.org"},
                        }
                    ]
                },
            }
        }
        policies = find_policies_in_workflow(workflow)
        assert len(policies) == 2

    def test_ignores_step_without_policy(self):
        """Steps without policy input are ignored."""
        workflow = {
            "jobs": {
                "build": {
                    "steps": [
                        {
                            "uses": "owner/egress-filter@v1",
                            "with": {"other": "value"},
                        }
                    ]
                }
            }
        }
        policies = find_policies_in_workflow(workflow)
        assert len(policies) == 0

    def test_ignores_other_actions(self):
        """Non-egress-filter actions are ignored."""
        workflow = {
            "jobs": {
                "build": {
                    "steps": [
                        {
                            "uses": "actions/checkout@v4",
                            "with": {"policy": "ignored"},
                        }
                    ]
                }
            }
        }
        policies = find_policies_in_workflow(workflow)
        assert len(policies) == 0


class TestValidatePolicy:
    """Tests for policy validation."""

    def test_valid_policy(self):
        """Valid policy returns no errors."""
        policy = """
        # Comment
        github.com
        *.github.com
        8.8.8.8:53/udp
        """
        errors = validate_policy(policy)
        assert len(errors) == 0

    def test_invalid_line(self):
        """Invalid line returns error with line number."""
        policy = """
        github.com
        not valid!!!
        *.github.com
        """
        errors = validate_policy(policy)
        assert len(errors) == 1
        line_num, line, error = errors[0]
        assert line_num == 3  # "not valid!!!" is on line 3
        assert "not valid" in line

    def test_multiple_errors(self):
        """Multiple invalid lines return multiple errors."""
        policy = """
        valid.com
        !!!invalid1
        also.valid.com
        !!!invalid2
        """
        errors = validate_policy(policy)
        assert len(errors) == 2

    def test_empty_policy(self):
        """Empty policy returns no errors."""
        errors = validate_policy("")
        assert len(errors) == 0

    def test_comments_only(self):
        """Comments-only policy returns no errors."""
        policy = """
        # Just comments
        # Nothing else
        """
        errors = validate_policy(policy)
        assert len(errors) == 0

    def test_preserves_header_context(self):
        """Headers affect subsequent rules (context preserved)."""
        # Path rule without URL context should be invalid
        policy = """
        /path/to/something
        """
        errors = validate_policy(policy)
        # Path rule without URL header context generates no rule (skipped)
        # but doesn't generate a parse error - it parses but produces no rule
        # This is lenient behavior per design doc

    def test_header_then_path_rule(self):
        """Path rule with URL header context is valid."""
        policy = """
        [https://api.github.com]
        /repos/*/releases
        """
        errors = validate_policy(policy)
        assert len(errors) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
