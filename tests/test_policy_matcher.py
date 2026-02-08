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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
