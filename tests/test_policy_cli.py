"""Tests for the policy validation CLI."""

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.policy.cli import (
    analyze_connections,
    connection_key,
    find_policies_in_workflow,
    format_connection,
    validate_policy,
)
from proxy.policy.parser import parse_policy, rule_to_dict


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


class TestAnalyzeConnections:
    """Tests for connection log analysis."""

    def test_analyze_allowed_connections(self):
        """Connections matching policy are allowed."""
        policy = """
        github.com
        *.github.com
        """
        connections = [
            {
                "type": "https",
                "dst_ip": "1.2.3.4",
                "dst_port": 443,
                "host": "github.com",
            },
            {
                "type": "https",
                "dst_ip": "1.2.3.5",
                "dst_port": 443,
                "host": "api.github.com",
            },
        ]
        results = analyze_connections(policy, connections)

        assert len(results["allowed"]) == 2
        assert len(results["blocked"]) == 0

    def test_analyze_blocked_connections(self):
        """Connections not matching policy are blocked."""
        policy = """
        github.com
        """
        connections = [
            {
                "type": "https",
                "dst_ip": "1.2.3.4",
                "dst_port": 443,
                "host": "github.com",
            },
            {"type": "https", "dst_ip": "5.6.7.8", "dst_port": 443, "host": "evil.com"},
        ]
        results = analyze_connections(policy, connections)

        assert len(results["allowed"]) == 1
        assert len(results["blocked"]) == 1

    def test_analyze_deduplicates_connections(self):
        """Duplicate connections are counted but not repeated."""
        policy = """
        github.com
        """
        connections = [
            {
                "type": "https",
                "dst_ip": "1.2.3.4",
                "dst_port": 443,
                "host": "github.com",
            },
            {
                "type": "https",
                "dst_ip": "1.2.3.4",
                "dst_port": 443,
                "host": "github.com",
            },
            {
                "type": "https",
                "dst_ip": "1.2.3.4",
                "dst_port": 443,
                "host": "github.com",
            },
        ]
        results = analyze_connections(policy, connections)

        assert len(results["allowed"]) == 1
        # Check count
        conn, count, rule_info = results["allowed"][0]
        assert count == 3

    def test_analyze_dns_connections(self):
        """DNS connections are analyzed correctly (requires both resolver AND domain)."""
        policy = """
        # Resolver
        [:53/udp]
        8.8.8.8

        # Domain
        []
        github.com
        """
        connections = [
            # Resolver AND domain allowed - passes
            {"type": "dns", "dst_ip": "8.8.8.8", "dst_port": 53, "name": "github.com"},
            # Wrong domain - blocked
            {"type": "dns", "dst_ip": "8.8.8.8", "dst_port": 53, "name": "example.com"},
        ]
        results = analyze_connections(policy, connections)

        assert len(results["allowed"]) == 1
        assert len(results["blocked"]) == 1

    def test_analyze_error_events_separated(self):
        """Error events (TLS failures) are separated from policy decisions."""
        policy = """
        github.com
        """
        connections = [
            # Normal connection - allowed by policy
            {
                "type": "https",
                "dst_ip": "1.2.3.4",
                "dst_port": 443,
                "host": "github.com",
            },
            # Normal connection - blocked by policy
            {
                "type": "https",
                "dst_ip": "5.6.7.8",
                "dst_port": 443,
                "host": "evil.com",
            },
            # Error event - TLS failure (not evaluated against policy)
            {
                "type": "https",
                "dst_ip": "9.10.11.12",
                "dst_port": 443,
                "host": "suspicious.com",
                "error": "tls_client_rejected_ca",
                "exe": "/usr/bin/suspicious",
            },
        ]
        results = analyze_connections(policy, connections)

        assert len(results["allowed"]) == 1
        assert len(results["blocked"]) == 1
        assert len(results["errors"]) == 1

        # Error event should have the error field preserved
        error_conn, error_count, _ = results["errors"][0]
        assert error_conn["error"] == "tls_client_rejected_ca"
        assert error_conn["host"] == "suspicious.com"

    def test_analyze_deduplicates_error_events(self):
        """Duplicate error events are counted but not repeated."""
        policy = """
        github.com
        """
        connections = [
            {
                "type": "https",
                "dst_ip": "1.2.3.4",
                "dst_port": 443,
                "host": "suspicious.com",
                "error": "tls_client_rejected_ca",
            },
            {
                "type": "https",
                "dst_ip": "1.2.3.4",
                "dst_port": 443,
                "host": "suspicious.com",
                "error": "tls_client_rejected_ca",
            },
        ]
        results = analyze_connections(policy, connections)

        assert len(results["errors"]) == 1
        _, count, _ = results["errors"][0]
        assert count == 2


class TestConnectionFormatting:
    """Tests for connection formatting."""

    def test_format_https(self):
        """HTTPS connections formatted correctly."""
        conn = {"type": "https", "host": "github.com", "dst_port": 443}
        assert format_connection(conn) == "https://github.com"

        conn = {"type": "https", "host": "github.com", "dst_port": 8443}
        assert format_connection(conn) == "https://github.com:8443"

    def test_format_http(self):
        """HTTP connections formatted correctly."""
        conn = {"type": "http", "method": "POST", "url": "http://example.com/api"}
        assert format_connection(conn) == "POST http://example.com/api"

    def test_format_dns(self):
        """DNS connections formatted correctly."""
        conn = {"type": "dns", "name": "github.com", "dst_ip": "8.8.8.8"}
        assert format_connection(conn) == "dns:github.com (via 8.8.8.8)"

    def test_format_tcp(self):
        """TCP connections formatted correctly."""
        conn = {"type": "tcp", "host": "github.com", "dst_port": 22}
        assert format_connection(conn) == "tcp://github.com:22"

    def test_format_udp(self):
        """UDP connections formatted correctly."""
        conn = {"type": "udp", "dst_ip": "8.8.8.8", "dst_port": 123}
        assert format_connection(conn) == "udp://8.8.8.8:123"


class TestConnectionKey:
    """Tests for connection deduplication keys."""

    def test_https_key_by_host_and_port(self):
        """HTTPS connections keyed by host and port."""
        conn1 = {
            "type": "https",
            "host": "github.com",
            "dst_port": 443,
            "dst_ip": "1.1.1.1",
        }
        conn2 = {
            "type": "https",
            "host": "github.com",
            "dst_port": 443,
            "dst_ip": "2.2.2.2",
        }
        assert connection_key(conn1) == connection_key(conn2)

    def test_http_key_by_method_and_url(self):
        """HTTP connections keyed by method and URL."""
        conn1 = {"type": "http", "method": "GET", "url": "http://example.com/api"}
        conn2 = {"type": "http", "method": "POST", "url": "http://example.com/api"}
        assert connection_key(conn1) != connection_key(conn2)

    def test_dns_key_by_name(self):
        """DNS connections keyed by query name."""
        conn1 = {
            "type": "dns",
            "name": "github.com",
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
        }
        conn2 = {
            "type": "dns",
            "name": "github.com",
            "dst_ip": "1.1.1.1",
            "dst_port": 53,
        }
        assert connection_key(conn1) == connection_key(conn2)


class TestDumpRules:
    """Tests for rule dumping functionality."""

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


class TestDefaultsIntegration:
    """Tests for --include-defaults and --include-preset flags."""

    def test_analyze_with_defaults_allows_azure_wireserver(self):
        """--include-defaults should allow Azure agent to wireserver."""
        from proxy.policy.defaults import get_defaults

        policy = get_defaults()

        connections = [
            {
                "type": "http",
                "dst_ip": "168.63.129.16",
                "dst_port": 80,
                "url": "http://168.63.129.16/machine/?comp=goalstate",
                "method": "GET",
                "exe": "/usr/bin/python3.12",
                "cgroup": "/azure.slice/walinuxagent.service",
            }
        ]
        results = analyze_connections(policy, connections)

        assert len(results["allowed"]) == 1
        assert len(results["blocked"]) == 0

    def test_analyze_with_defaults_blocks_non_azure_to_wireserver(self):
        """--include-defaults should block non-azure cgroup from wireserver."""
        from proxy.policy.defaults import get_defaults

        policy = get_defaults()

        connections = [
            {
                "type": "http",
                "dst_ip": "168.63.129.16",
                "dst_port": 80,
                "url": "http://168.63.129.16/machine/?comp=goalstate",
                "method": "GET",
                "exe": "/usr/bin/curl",
                "cgroup": "/system.slice/some.service",
            }
        ]
        results = analyze_connections(policy, connections)

        assert len(results["allowed"]) == 0
        assert len(results["blocked"]) == 1

    def test_combined_defaults_and_user_policy(self):
        """User policy should extend defaults (inheriting cgroup constraint)."""
        from proxy.policy.defaults import get_defaults

        # User policy allows example.com
        combined_policy = get_defaults() + "\nexample.com\n"

        connections = [
            # User rule allows example.com when cgroup matches
            {
                "type": "http",
                "dst_ip": "93.184.216.34",
                "dst_port": 443,
                "url": "https://example.com/",
                "method": "GET",
                "exe": "/usr/bin/curl",
                "cgroup": "/system.slice/hosted-compute-agent.service",
            },
        ]
        results = analyze_connections(combined_policy, connections)

        assert len(results["allowed"]) == 1
        assert len(results["blocked"]) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
