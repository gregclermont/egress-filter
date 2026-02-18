"""Tests for policy enforcement: end-to-end enforcer scenarios.

Uses YAML test fixtures from tests/fixtures/.
"""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.policy import (
    DNSIPCache,
    PolicyEnforcer,
    PolicyMatcher,
    ProcessInfo,
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

        # Check insecure flag if specified in fixture
        if "insecure" in check:
            expected_insecure = check["insecure"]
            assert decision.insecure == expected_insecure, (
                f"Scenario '{scenario['name']}', check {i} ({check_type}):\n"
                f"Check: {check}\n"
                f"Expected insecure: {expected_insecure}, Got: {decision.insecure}"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
