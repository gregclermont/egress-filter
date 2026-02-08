"""Tests for the policy validation CLI."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.cli import (
    analyze_connections,
    connection_key,
    find_policies_in_workflow,
    format_connection,
)
from proxy.policy.parser import validate_policy


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

    def test_path_without_url_context(self):
        """Path rule without URL header context is reported as error."""
        policy = """
        /path/to/something
        """
        errors = validate_policy(policy)
        assert len(errors) == 1
        _, _, message = errors[0]
        assert "URL header context" in message

    def test_header_then_path_rule(self):
        """Path rule with URL header context is valid."""
        policy = """
        [https://api.github.com]
        /repos/*/releases
        """
        errors = validate_policy(policy)
        assert len(errors) == 0

    def test_passthrough_on_ip_returns_error(self):
        """Passthrough on IP rule is reported as error."""
        errors = validate_policy("8.8.8.8 passthrough")
        assert len(errors) == 1
        _, _, message = errors[0]
        assert "passthrough" in message
        assert "ip" in message

    def test_passthrough_on_cidr_returns_error(self):
        """Passthrough on CIDR under header is reported as error."""
        errors = validate_policy("[passthrough]\n10.0.0.0/8")
        assert len(errors) == 1
        _, _, message = errors[0]
        assert "passthrough" in message
        assert "cidr" in message

    def test_passthrough_on_dns_returns_error(self):
        """Passthrough on dns: rule is reported as error."""
        errors = validate_policy("dns:example.com passthrough")
        assert len(errors) == 1
        _, _, message = errors[0]
        assert "passthrough" in message

    def test_passthrough_header_mixed_valid_invalid(self):
        """Passthrough header with mix of valid hosts and invalid CIDR."""
        policy = "[passthrough]\ngithub.com\n10.0.0.0/8\n*.docker.io"
        errors = validate_policy(policy)
        assert len(errors) == 1
        line_num, line, message = errors[0]
        assert line_num == 3
        assert "10.0.0.0/8" in line

    def test_passthrough_on_hostname_is_valid(self):
        """Passthrough on hostname rule is valid."""
        errors = validate_policy("github.com passthrough")
        assert len(errors) == 0

    def test_passthrough_on_wildcard_is_valid(self):
        """Passthrough on wildcard rule is valid."""
        errors = validate_policy("*.docker.io passthrough")
        assert len(errors) == 0

    def test_passthrough_overlaps_url_rule(self):
        """Passthrough on hostname that has URL/path rules warns about overlap."""
        policy = "https://example.com/api/*\nexample.com passthrough"
        errors = validate_policy(policy)
        assert len(errors) == 1
        _, _, message = errors[0]
        assert "overlaps" in message
        assert "example.com" in message
        assert "URL path" in message

    def test_passthrough_wildcard_overlaps_url_rule(self):
        """Wildcard passthrough overlapping URL rule hostname warns."""
        policy = "https://api.example.com/v1/*\n*.example.com passthrough"
        errors = validate_policy(policy)
        assert len(errors) == 1
        _, _, message = errors[0]
        assert "overlaps" in message

    def test_passthrough_no_overlap_no_warning(self):
        """Passthrough on different hostname than URL rules produces no warning."""
        policy = "https://example.com/api/*\nother.com passthrough"
        errors = validate_policy(policy)
        assert len(errors) == 0

    def test_passthrough_overlaps_path_rule(self):
        """Passthrough overlapping a path rule under URL header warns."""
        policy = "[https://example.com]\n/api/*\n[]\nexample.com passthrough"
        errors = validate_policy(policy)
        assert len(errors) == 1
        _, _, message = errors[0]
        assert "overlaps" in message


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

    def test_analyze_dns_response_skipped_for_policy(self):
        """dns_response entries are not evaluated against policy."""
        policy = """
        [:53/udp]
        8.8.8.8
        []
        github.com
        """
        connections = [
            {"type": "dns", "dst_ip": "8.8.8.8", "dst_port": 53, "name": "github.com"},
            {
                "type": "dns_response",
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "name": "github.com",
                "answers": ["140.82.113.4"],
                "ttl": 300,
            },
        ]
        results = analyze_connections(policy, connections)

        # Only the dns request should be counted, not the dns_response
        assert len(results["allowed"]) == 1
        assert results["allowed"][0][0]["type"] == "dns"
        assert len(results["blocked"]) == 0

    def test_analyze_dns_response_populates_cache_for_tcp(self):
        """dns_response answers enable hostname matching for TCP connections."""
        policy = """
        github.com
        """
        connections = [
            # dns_response provides IP -> hostname mapping
            {
                "type": "dns_response",
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "name": "github.com",
                "answers": ["140.82.113.4", "140.82.113.5"],
                "ttl": 300,
            },
            # TCP connection to one of the resolved IPs
            {
                "type": "tcp",
                "dst_ip": "140.82.113.4",
                "dst_port": 443,
            },
            # TCP connection to another resolved IP
            {
                "type": "tcp",
                "dst_ip": "140.82.113.5",
                "dst_port": 443,
            },
            # TCP to unrelated IP - should be blocked
            {
                "type": "tcp",
                "dst_ip": "1.2.3.4",
                "dst_port": 443,
            },
        ]
        results = analyze_connections(policy, connections)

        assert len(results["allowed"]) == 2
        assert len(results["blocked"]) == 1

    def test_analyze_dns_response_without_answers_ignored(self):
        """dns_response entries without answers don't affect cache."""
        policy = """
        github.com
        """
        connections = [
            # dns_response with empty answers (e.g., NXDOMAIN)
            {
                "type": "dns_response",
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "name": "github.com",
                "answers": [],
            },
            # TCP connection - no DNS cache entry, so no hostname match
            {
                "type": "tcp",
                "dst_ip": "140.82.113.4",
                "dst_port": 443,
            },
        ]
        results = analyze_connections(policy, connections)

        assert len(results["allowed"]) == 0
        assert len(results["blocked"]) == 1

    def test_analyze_mitmed_https_with_url_rules(self):
        """MITMed HTTPS connections (with url field) match URL rules."""
        policy = """
        GET https://github.com/owner/repo/info/refs
        POST https://github.com/owner/repo/git-upload-pack
        """
        connections = [
            {
                "type": "https",
                "dst_ip": "140.82.113.4",
                "dst_port": 443,
                "url": "https://github.com/owner/repo/info/refs?service=git-upload-pack",
                "method": "GET",
            },
            {
                "type": "https",
                "dst_ip": "140.82.113.4",
                "dst_port": 443,
                "url": "https://github.com/owner/repo/git-upload-pack",
                "method": "POST",
            },
        ]
        results = analyze_connections(policy, connections)

        assert len(results["allowed"]) == 2
        assert len(results["blocked"]) == 0

    def test_analyze_mitmed_https_deduplicates_by_url(self):
        """MITMed HTTPS connections are deduplicated by method + URL."""
        policy = """
        github.com
        """
        connections = [
            {
                "type": "https",
                "dst_ip": "140.82.113.4",
                "dst_port": 443,
                "url": "https://github.com/owner/repo/info/refs",
                "method": "GET",
            },
            {
                "type": "https",
                "dst_ip": "140.82.113.5",
                "dst_port": 443,
                "url": "https://github.com/owner/repo/info/refs",
                "method": "GET",
            },
        ]
        results = analyze_connections(policy, connections)

        assert len(results["allowed"]) == 1
        conn, count, _ = results["allowed"][0]
        assert count == 2

    def test_analyze_non_mitmed_https_still_uses_sni(self):
        """Non-MITMed HTTPS connections (no url, has host) use check_https."""
        policy = """
        github.com
        """
        connections = [
            {
                "type": "https",
                "dst_ip": "140.82.113.4",
                "dst_port": 443,
                "host": "github.com",
            },
        ]
        results = analyze_connections(policy, connections)

        assert len(results["allowed"]) == 1
        assert len(results["blocked"]) == 0

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

    def test_format_mitmed_https(self):
        """MITMed HTTPS connections (with url) show method + URL."""
        conn = {
            "type": "https",
            "dst_ip": "140.82.113.4",
            "dst_port": 443,
            "url": "https://github.com/owner/repo/info/refs",
            "method": "GET",
        }
        assert format_connection(conn) == "GET https://github.com/owner/repo/info/refs"

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
        """Non-MITMed HTTPS connections keyed by host and port."""
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

    def test_mitmed_https_key_by_method_and_url(self):
        """MITMed HTTPS connections (with url) keyed by method + URL."""
        conn1 = {
            "type": "https",
            "dst_ip": "1.1.1.1",
            "dst_port": 443,
            "url": "https://github.com/owner/repo/info/refs",
            "method": "GET",
        }
        conn2 = {
            "type": "https",
            "dst_ip": "2.2.2.2",
            "dst_port": 443,
            "url": "https://github.com/owner/repo/info/refs",
            "method": "GET",
        }
        assert connection_key(conn1) == connection_key(conn2)

    def test_mitmed_https_different_urls_different_keys(self):
        """MITMed HTTPS connections with different URLs get different keys."""
        conn1 = {
            "type": "https",
            "dst_ip": "1.1.1.1",
            "dst_port": 443,
            "url": "https://github.com/owner/repo/info/refs",
            "method": "GET",
        }
        conn2 = {
            "type": "https",
            "dst_ip": "1.1.1.1",
            "dst_port": 443,
            "url": "https://github.com/owner/repo/git-upload-pack",
            "method": "POST",
        }
        assert connection_key(conn1) != connection_key(conn2)

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
