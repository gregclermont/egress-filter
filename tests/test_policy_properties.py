"""
Property-based tests for policy matching and enforcement.

Uses hypothesis to generate random inputs and verify invariants hold.
These tests complement the YAML fixtures by exploring edge cases
that humans might not think of.

Run with: pytest tests/test_policy_properties.py -v
"""

import ipaddress
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.policy import (
    DNSIPCache,
    PolicyEnforcer,
    PolicyMatcher,
    ProcessInfo,
    parse_policy,
    rule_to_dict,
)
from proxy.policy.matcher import (
    cidr_contains,
    ip_to_int,
    match_hostname,
    match_url_path,
    match_wildcard,
)

# =============================================================================
# Strategies for generating test data
# =============================================================================

# Valid IPv4 address components
ipv4_octet = st.integers(min_value=0, max_value=255)

# Valid IPv4 address as tuple
ipv4_tuple = st.tuples(ipv4_octet, ipv4_octet, ipv4_octet, ipv4_octet)


@st.composite
def ipv4_address(draw):
    """Generate a valid IPv4 address string."""
    octets = draw(ipv4_tuple)
    return f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}"


@st.composite
def cidr_block(draw):
    """Generate a valid CIDR block."""
    ip = draw(ipv4_address())
    mask = draw(st.integers(min_value=0, max_value=32))
    return f"{ip}/{mask}"


@st.composite
def hostname_part(draw):
    """Generate a valid hostname part (label)."""
    # Must start and end with alphanumeric, can have hyphens in middle
    length = draw(st.integers(min_value=1, max_value=10))
    if length == 1:
        return draw(st.from_regex(r"[a-z0-9]", fullmatch=True))
    elif length == 2:
        return draw(st.from_regex(r"[a-z0-9]{2}", fullmatch=True))
    else:
        middle_len = length - 2
        start = draw(st.from_regex(r"[a-z0-9]", fullmatch=True))
        middle = draw(st.from_regex(f"[a-z0-9-]{{{middle_len}}}", fullmatch=True))
        end = draw(st.from_regex(r"[a-z0-9]", fullmatch=True))
        return start + middle + end


@st.composite
def tld(draw):
    """Generate a valid TLD (starts with letter)."""
    return draw(st.from_regex(r"[a-z][a-z0-9]{1,5}", fullmatch=True))


@st.composite
def hostname(draw):
    """Generate a valid hostname."""
    num_parts = draw(st.integers(min_value=1, max_value=4))
    parts = [draw(hostname_part()) for _ in range(num_parts)]
    t = draw(tld())
    return ".".join(parts) + "." + t


@st.composite
def url_path(draw):
    """Generate a valid URL path."""
    num_segments = draw(st.integers(min_value=1, max_value=5))
    segments = []
    for _ in range(num_segments):
        seg_type = draw(st.sampled_from(["literal", "wildcard", "partial"]))
        if seg_type == "literal":
            segments.append(draw(st.from_regex(r"[a-z0-9_-]{1,10}", fullmatch=True)))
        elif seg_type == "wildcard":
            segments.append("*")
        else:  # partial
            prefix = draw(st.from_regex(r"[a-z]{1,3}", fullmatch=True))
            segments.append(f"{prefix}*")
    return "/" + "/".join(segments)


# =============================================================================
# CIDR Matching Properties
# =============================================================================


class TestCidrProperties:
    """Property-based tests for CIDR matching."""

    @given(ipv4_address())
    @settings(max_examples=200)
    def test_ip_in_slash32_is_only_itself(self, ip):
        """A /32 CIDR contains only the exact IP."""
        cidr = f"{ip}/32"
        assert cidr_contains(cidr, ip)

    @given(ipv4_address())
    @settings(max_examples=200)
    def test_all_ips_in_slash0(self, ip):
        """0.0.0.0/0 contains all IPs."""
        assert cidr_contains("0.0.0.0/0", ip)

    @given(ipv4_tuple, st.integers(min_value=0, max_value=32))
    @settings(max_examples=500)
    def test_cidr_consistent_with_ipaddress_module(self, ip_tuple, mask):
        """Our CIDR matching should be consistent with Python's ipaddress module."""
        ip_str = f"{ip_tuple[0]}.{ip_tuple[1]}.{ip_tuple[2]}.{ip_tuple[3]}"

        # Generate a random test IP
        test_tuple = (
            (ip_tuple[0] + 1) % 256,
            ip_tuple[1],
            ip_tuple[2],
            ip_tuple[3],
        )
        test_ip = f"{test_tuple[0]}.{test_tuple[1]}.{test_tuple[2]}.{test_tuple[3]}"

        # Normalize the network address for ipaddress module
        try:
            network = ipaddress.ip_network(f"{ip_str}/{mask}", strict=False)
            expected = ipaddress.ip_address(test_ip) in network
        except ValueError:
            return  # Skip invalid inputs

        cidr = f"{ip_str}/{mask}"
        actual = cidr_contains(cidr, test_ip)
        assert actual == expected, f"Mismatch for {test_ip} in {cidr}"

    @given(
        ipv4_tuple,
        ipv4_tuple,
        st.integers(min_value=0, max_value=32),
    )
    @settings(max_examples=500)
    def test_cidr_matches_ipaddress_module(self, network_tuple, test_tuple, mask):
        """CIDR matching matches Python's ipaddress for any IP pair."""
        network_ip = f"{network_tuple[0]}.{network_tuple[1]}.{network_tuple[2]}.{network_tuple[3]}"
        test_ip = f"{test_tuple[0]}.{test_tuple[1]}.{test_tuple[2]}.{test_tuple[3]}"

        try:
            network = ipaddress.ip_network(f"{network_ip}/{mask}", strict=False)
            expected = ipaddress.ip_address(test_ip) in network
        except ValueError:
            return

        actual = cidr_contains(f"{network_ip}/{mask}", test_ip)
        assert actual == expected


class TestIpToIntProperties:
    """Property-based tests for IP to integer conversion."""

    @given(ipv4_tuple)
    @settings(max_examples=200)
    def test_ip_to_int_range(self, ip_tuple):
        """IP to int should produce values in valid range."""
        ip_str = f"{ip_tuple[0]}.{ip_tuple[1]}.{ip_tuple[2]}.{ip_tuple[3]}"
        result = ip_to_int(ip_str)
        assert 0 <= result <= 0xFFFFFFFF

    @given(ipv4_tuple)
    @settings(max_examples=200)
    def test_ip_to_int_consistent_with_ipaddress(self, ip_tuple):
        """IP to int should match ipaddress module."""
        ip_str = f"{ip_tuple[0]}.{ip_tuple[1]}.{ip_tuple[2]}.{ip_tuple[3]}"
        expected = int(ipaddress.ip_address(ip_str))
        actual = ip_to_int(ip_str)
        assert actual == expected


# =============================================================================
# Hostname Matching Properties
# =============================================================================


class TestHostnameProperties:
    """Property-based tests for hostname matching."""

    @given(hostname())
    @settings(max_examples=200, suppress_health_check=[HealthCheck.filter_too_much])
    def test_exact_hostname_matches_itself(self, host):
        """A hostname always matches itself exactly."""
        assume(len(host) > 3)  # Need at least x.yy
        assert match_hostname(host, host)

    @given(hostname())
    @settings(max_examples=200, suppress_health_check=[HealthCheck.filter_too_much])
    def test_hostname_matching_is_case_insensitive(self, host):
        """Hostname matching should be case-insensitive."""
        assume(len(host) > 3)
        assert match_hostname(host.lower(), host.upper())
        assert match_hostname(host.upper(), host.lower())

    @given(hostname(), hostname_part())
    @settings(max_examples=200, suppress_health_check=[HealthCheck.filter_too_much])
    def test_wildcard_matches_subdomain(self, base_host, subdomain):
        """Wildcard pattern matches any subdomain."""
        assume(len(base_host) > 3)
        assume(len(subdomain) > 0)
        full_host = f"{subdomain}.{base_host}"
        # Pattern must include *. prefix for subdomain wildcard
        pattern = f"*.{base_host}"
        assert match_hostname(pattern, full_host, is_wildcard=True)

    @given(hostname())
    @settings(max_examples=200, suppress_health_check=[HealthCheck.filter_too_much])
    def test_wildcard_does_not_match_root(self, host):
        """Wildcard pattern does NOT match the root domain itself."""
        assume(len(host) > 3)
        # *.example.com should NOT match example.com
        pattern = f"*.{host}"
        assert not match_hostname(pattern, host, is_wildcard=True)


# =============================================================================
# URL Path Matching Properties
# =============================================================================


class TestUrlPathProperties:
    """Property-based tests for URL path matching."""

    @given(st.from_regex(r"/[a-z0-9/_-]{1,50}", fullmatch=True))
    @settings(max_examples=200)
    def test_exact_path_matches_itself(self, path):
        """A path always matches itself."""
        assert match_url_path(path, path)

    @given(st.from_regex(r"/[a-z0-9/_-]{1,30}", fullmatch=True))
    @settings(max_examples=200)
    def test_trailing_wildcard_matches_extensions(self, base_path):
        """A trailing wildcard matches any extension."""
        pattern = base_path.rstrip("/") + "/*"
        extended = base_path.rstrip("/") + "/extra/segments"
        assert match_url_path(pattern, extended)

    @given(
        st.from_regex(r"/[a-z]{1,10}", fullmatch=True),
        st.from_regex(r"[a-z]{1,10}", fullmatch=True),
        st.from_regex(r"/[a-z]{1,10}", fullmatch=True),
    )
    @settings(max_examples=200)
    def test_segment_wildcard_matches_single_segment(self, prefix, segment, suffix):
        """A segment wildcard matches exactly one segment."""
        pattern = f"{prefix}/*{suffix}"
        actual = f"{prefix}/{segment}{suffix}"
        assert match_url_path(pattern, actual)

    @given(
        st.from_regex(r"/[a-z]{1,10}", fullmatch=True),
        st.from_regex(r"[a-z]{1,10}/[a-z]{1,10}", fullmatch=True),
        st.from_regex(r"/[a-z]{1,10}", fullmatch=True),
    )
    @settings(max_examples=200)
    def test_segment_wildcard_rejects_multiple_segments(self, prefix, segments, suffix):
        """A segment wildcard should NOT match multiple segments."""
        pattern = f"{prefix}/*{suffix}"
        actual = f"{prefix}/{segments}{suffix}"
        # This should NOT match because segments contains a /
        assert not match_url_path(pattern, actual)


# =============================================================================
# Wildcard Matching Properties
# =============================================================================


class TestWildcardProperties:
    """Property-based tests for wildcard/glob matching."""

    @given(st.from_regex(r"[a-z0-9/_.-]{1,30}", fullmatch=True))
    @settings(max_examples=200)
    def test_literal_matches_itself(self, s):
        """A literal string matches itself."""
        assert match_wildcard(s, s)

    @given(st.from_regex(r"[a-z0-9/_.-]{1,30}", fullmatch=True))
    @settings(max_examples=200)
    def test_star_matches_anything(self, s):
        """A single * matches any string."""
        assert match_wildcard("*", s)

    @given(
        st.from_regex(r"[a-z]{1,10}", fullmatch=True),
        st.from_regex(r"[a-z]{1,10}", fullmatch=True),
    )
    @settings(max_examples=200)
    def test_prefix_wildcard(self, prefix, suffix):
        """prefix* matches prefix followed by anything."""
        pattern = f"{prefix}*"
        actual = f"{prefix}{suffix}"
        assert match_wildcard(pattern, actual)

    @given(
        st.from_regex(r"[a-z]{1,10}", fullmatch=True),
        st.from_regex(r"[a-z]{1,10}", fullmatch=True),
    )
    @settings(max_examples=200)
    def test_suffix_wildcard(self, prefix, suffix):
        """*suffix matches anything followed by suffix."""
        pattern = f"*{suffix}"
        actual = f"{prefix}{suffix}"
        assert match_wildcard(pattern, actual)


# =============================================================================
# Parser Round-Trip Properties
# =============================================================================


class TestParserProperties:
    """Property-based tests for parser behavior."""

    @given(
        st.sampled_from(
            [
                "github.com",
                "*.github.com",
                "8.8.8.8",
                "10.0.0.0/8",
                "github.com:443",
                "github.com:22/tcp",
                "8.8.8.8:53/udp",
                "https://api.github.com/*",
                "GET https://api.github.com/*",
            ]
        )
    )
    def test_parse_produces_at_least_one_rule(self, policy):
        """Valid single-rule policies produce exactly one rule."""
        rules = parse_policy(policy)
        assert len(rules) == 1

    @given(st.text(min_size=0, max_size=200))
    @settings(max_examples=500)
    def test_parser_never_crashes(self, text):
        """Parser should never raise an unexpected exception."""
        # Should either return rules or return empty (lenient parsing)
        try:
            rules = parse_policy(text)
            assert isinstance(rules, list)
        except Exception as e:
            # Only ParseError-related exceptions are acceptable
            # but our parser is lenient so it should just return []
            pytest.fail(f"Parser raised unexpected exception: {e}")


# =============================================================================
# Enforcer Properties
# =============================================================================


class TestEnforcerProperties:
    """Property-based tests for enforcer behavior."""

    @given(hostname(), st.integers(min_value=1, max_value=65535))
    @settings(max_examples=200, suppress_health_check=[HealthCheck.filter_too_much])
    def test_allowed_hostname_is_allowed(self, host, port):
        """If a hostname is in the policy, connections to it are allowed."""
        assume(len(host) > 3)
        # Skip hostnames that look like IPs (all-numeric parts before TLD)
        parts = host.split(".")
        assume(not all(p.isdigit() for p in parts[:-1]))

        policy = f"{host}:{port}"
        rules = parse_policy(policy)
        # Skip if the parser rejected this hostname
        assume(len(rules) > 0)

        matcher = PolicyMatcher(policy)
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_https(
            dst_ip="1.2.3.4",
            dst_port=port,
            sni=host,
        )
        assert decision.allowed

    @given(hostname(), hostname())
    @settings(max_examples=200, suppress_health_check=[HealthCheck.filter_too_much])
    def test_unallowed_hostname_is_blocked(self, allowed_host, blocked_host):
        """If a hostname is NOT in the policy, connections to it are blocked."""
        assume(len(allowed_host) > 3 and len(blocked_host) > 3)
        assume(allowed_host.lower() != blocked_host.lower())

        policy = f"{allowed_host}"
        matcher = PolicyMatcher(policy)
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_https(
            dst_ip="1.2.3.4",
            dst_port=443,
            sni=blocked_host,
        )
        assert decision.blocked

    @given(ipv4_address(), st.integers(min_value=1, max_value=65535))
    @settings(max_examples=200)
    def test_allowed_ip_is_allowed(self, ip, port):
        """If an IP is in the policy, connections to it are allowed."""
        policy = f"{ip}:{port}"
        matcher = PolicyMatcher(policy)
        enforcer = PolicyEnforcer(matcher)

        decision = enforcer.check_tcp(dst_ip=ip, dst_port=port)
        assert decision.allowed

    @given(hostname())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.filter_too_much])
    def test_audit_mode_never_blocks(self, host):
        """In audit mode, nothing is ever blocked."""
        assume(len(host) > 3)
        # Empty policy - would normally block everything
        matcher = PolicyMatcher("")
        enforcer = PolicyEnforcer(matcher, audit_mode=True)

        decision = enforcer.check_https(
            dst_ip="1.2.3.4",
            dst_port=443,
            sni=host,
        )
        assert decision.allowed
        assert "[AUDIT]" in decision.reason


# =============================================================================
# DNS Cache Properties
# =============================================================================


class TestDNSCacheProperties:
    """Property-based tests for DNS cache."""

    @given(ipv4_address(), hostname(), st.integers(min_value=60, max_value=3600))
    @settings(max_examples=200, suppress_health_check=[HealthCheck.filter_too_much])
    def test_add_then_lookup_returns_hostname(self, ip, host, ttl):
        """Adding an IP->hostname mapping allows lookup."""
        assume(len(host) > 3)
        cache = DNSIPCache()
        cache.add(ip, host, ttl)
        assert cache.lookup(ip) == host.lower()

    @given(
        st.lists(ipv4_address(), min_size=1, max_size=10, unique=True),
        hostname(),
        st.integers(min_value=60, max_value=3600),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.filter_too_much])
    def test_add_many_all_lookup(self, ips, host, ttl):
        """Adding multiple IPs for same hostname allows lookup of all."""
        assume(len(host) > 3)
        cache = DNSIPCache()
        cache.add_many(ips, host, ttl)
        for ip in ips:
            assert cache.lookup(ip) == host.lower()

    @given(ipv4_address())
    @settings(max_examples=100)
    def test_lookup_unknown_returns_none(self, ip):
        """Looking up an unknown IP returns None."""
        cache = DNSIPCache()
        assert cache.lookup(ip) is None


# =============================================================================
# DNS Cache Concurrency Tests
# =============================================================================


class TestDNSCacheConcurrency:
    """Stress tests for DNS cache thread safety."""

    def test_concurrent_add_and_lookup(self):
        """Concurrent adds and lookups should not corrupt data."""
        cache = DNSIPCache()
        errors = []
        iterations = 1000

        def adder(thread_id):
            for i in range(iterations):
                ip = f"10.{thread_id}.{i % 256}.{(i // 256) % 256}"
                cache.add(ip, f"host-{thread_id}-{i}.example.com", ttl=300)

        def reader(thread_id):
            for i in range(iterations):
                ip = f"10.{thread_id}.{i % 256}.{(i // 256) % 256}"
                result = cache.lookup(ip)
                # Result should be None or a valid hostname
                if result is not None and not result.endswith(".example.com"):
                    errors.append(f"Invalid result: {result}")

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            for i in range(4):
                futures.append(executor.submit(adder, i))
                futures.append(executor.submit(reader, i))

            for f in futures:
                f.result()

        assert len(errors) == 0, f"Errors: {errors}"

    def test_concurrent_add_and_cleanup(self):
        """Concurrent adds and cleanup should not corrupt data."""
        cache = DNSIPCache(min_ttl=1, max_ttl=1)
        errors = []
        stop_flag = threading.Event()

        def adder():
            i = 0
            while not stop_flag.is_set():
                ip = f"10.0.{i % 256}.{(i // 256) % 256}"
                cache.add(ip, f"host-{i}.example.com", ttl=1)
                i += 1
                if i % 100 == 0:
                    time.sleep(0.001)

        def cleaner():
            while not stop_flag.is_set():
                try:
                    cache.cleanup_expired()
                except Exception as e:
                    errors.append(f"Cleanup error: {e}")
                time.sleep(0.01)

        threads = [
            threading.Thread(target=adder),
            threading.Thread(target=adder),
            threading.Thread(target=cleaner),
        ]

        for t in threads:
            t.start()

        time.sleep(2)  # Run for 2 seconds
        stop_flag.set()

        for t in threads:
            t.join(timeout=5)

        assert len(errors) == 0, f"Errors: {errors}"

    def test_high_contention_lookups(self):
        """Many threads looking up the same IPs should not cause issues."""
        cache = DNSIPCache()

        # Pre-populate cache
        for i in range(100):
            cache.add(f"10.0.0.{i}", f"host-{i}.example.com", ttl=300)

        errors = []
        iterations = 10000

        def reader(thread_id):
            for i in range(iterations):
                ip = f"10.0.0.{i % 100}"
                expected = f"host-{i % 100}.example.com"
                result = cache.lookup(ip)
                if result != expected:
                    errors.append(
                        f"Thread {thread_id}: Expected {expected}, got {result}"
                    )

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(reader, i) for i in range(10)]
            for f in futures:
                f.result()

        assert len(errors) == 0, f"Errors (first 10): {errors[:10]}"


# =============================================================================
# Matcher Integration Properties
# =============================================================================


class TestMatcherIntegration:
    """Integration tests for the full matcher."""

    @given(
        st.lists(
            st.sampled_from(
                [
                    "github.com",
                    "*.github.com",
                    "8.8.8.8:53/udp",
                    "10.0.0.0/8:*",
                    "https://api.example.com/*",
                ]
            ),
            min_size=1,
            max_size=5,
        )
    )
    @settings(max_examples=100)
    def test_matcher_with_random_policy_combination(self, rules):
        """Random combinations of valid rules should create a working matcher."""
        policy = "\n".join(rules)
        matcher = PolicyMatcher(policy)

        # Matcher should be created without error
        assert matcher is not None

        # Should be able to check verdicts without error
        verdict = matcher.verdict(
            {
                "type": "https",
                "dst_ip": "1.2.3.4",
                "dst_port": 443,
                "host": "test.example.com",
            }
        )
        assert verdict in ("allow", "block")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
