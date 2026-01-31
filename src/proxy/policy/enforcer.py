"""Policy enforcer - makes allow/block decisions for connections.

This module provides a testable interface for policy enforcement.
The PolicyEnforcer class uses pure functions that don't depend on
mitmproxy or BPF types, making them easy to unit test.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol
from urllib.parse import urlparse

from .defaults import RUNNER_DEFAULTS, get_defaults
from .dns_cache import DNSIPCache
from .matcher import ConnectionEvent, PolicyMatcher
from .parser import parse_github_repository, substitute_placeholders
from .types import DefaultContext


class Verdict(Enum):
    """Policy decision verdict."""

    ALLOW = "allow"
    BLOCK = "block"


@dataclass
class Decision:
    """Result of a policy check.

    Attributes:
        verdict: Whether the connection is allowed or blocked (accounts for audit mode)
        reason: Human-readable explanation of the decision
        matched_rule: Index of the rule that matched (if allowed)
        hostname: Hostname used for matching (may be from DNS cache)
    """

    verdict: Verdict
    reason: str
    matched_rule: int | None = None
    hostname: str | None = None

    @property
    def allowed(self) -> bool:
        """Convenience property for checking if allowed."""
        return self.verdict == Verdict.ALLOW

    @property
    def blocked(self) -> bool:
        """Convenience property for checking if blocked."""
        return self.verdict == Verdict.BLOCK

    @property
    def policy(self) -> str:
        """Policy verdict as string: 'allow' if rule matched, 'deny' if not.

        This reflects what the policy says, independent of audit mode.
        """
        return "allow" if self.matched_rule is not None else "deny"


@dataclass
class ProcessInfo:
    """Process information for policy matching.

    This is a simplified view of process info that doesn't depend
    on /proc filesystem access, making it easy to construct in tests.
    """

    exe: str | None = None
    cmdline: list[str] | None = None
    cgroup: str | None = None
    step: str | None = None
    action: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "ProcessInfo":
        """Create ProcessInfo from a dict (e.g., from get_proc_info)."""
        return cls(
            exe=d.get("exe"),
            cmdline=d.get("cmdline"),
            cgroup=d.get("cgroup"),
            step=d.get("step"),
            action=d.get("action"),
        )

    def to_dict(self) -> dict:
        """Convert to dict for ConnectionEvent."""
        result = {}
        if self.exe:
            result["exe"] = self.exe
        if self.cmdline:
            result["cmdline"] = self.cmdline
        if self.cgroup:
            result["cgroup"] = self.cgroup
        if self.step:
            result["step"] = self.step
        if self.action:
            result["action"] = self.action
        return result


class PolicyEnforcer:
    """Makes policy decisions for network connections.

    This class provides pure functions for deciding whether to allow
    or block connections. It's designed to be easily testable without
    requiring mitmproxy or BPF infrastructure.

    Example:
        matcher = PolicyMatcher(policy_text)
        dns_cache = DNSIPCache()
        enforcer = PolicyEnforcer(matcher, dns_cache)

        # Check an HTTPS connection
        decision = enforcer.check_https(
            dst_ip="140.82.121.4",
            dst_port=443,
            sni="github.com",
            proc=ProcessInfo(exe="/usr/bin/curl")
        )

        if decision.blocked:
            # Block the connection
            ...
    """

    def __init__(
        self,
        matcher: PolicyMatcher,
        dns_cache: DNSIPCache | None = None,
        audit_mode: bool = False,
    ):
        """Initialize the enforcer.

        Args:
            matcher: Policy matcher with loaded rules
            dns_cache: DNS IP cache for hostname correlation (optional)
            audit_mode: If True, log but don't block (always allow)
        """
        self.matcher = matcher
        self.dns_cache = dns_cache or DNSIPCache()
        self.audit_mode = audit_mode

    def _make_decision(
        self,
        allowed: bool,
        rule_idx: int | None,
        reason: str,
        hostname: str | None = None,
    ) -> Decision:
        """Create a decision, respecting audit mode."""
        if self.audit_mode and not allowed:
            return Decision(
                verdict=Verdict.ALLOW,
                reason=f"[AUDIT] Would block: {reason}",
                matched_rule=None,
                hostname=hostname,
            )

        return Decision(
            verdict=Verdict.ALLOW if allowed else Verdict.BLOCK,
            reason=reason,
            matched_rule=rule_idx if allowed else None,
            hostname=hostname,
        )

    def check_https(
        self,
        dst_ip: str,
        dst_port: int,
        sni: str | None,
        proc: ProcessInfo | None = None,
    ) -> Decision:
        """Check an HTTPS connection (TLS with SNI).

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            sni: Server Name Indication (hostname from TLS ClientHello)
            proc: Process information

        Returns:
            Decision with verdict and reason
        """
        proc_dict = proc.to_dict() if proc else {}

        # If we have SNI, use it as the hostname
        if sni:
            event = ConnectionEvent(
                type="https",
                dst_ip=dst_ip,
                dst_port=dst_port,
                host=sni,
                **proc_dict,
            )
            allowed, rule_idx = self.matcher.match(event)

            if allowed:
                return self._make_decision(
                    True, rule_idx, f"Matched rule {rule_idx}", hostname=sni
                )
            else:
                return self._make_decision(
                    False,
                    None,
                    f"No rule matches https://{sni}:{dst_port}",
                    hostname=sni,
                )

        # No SNI - try DNS cache lookup
        cached_hostname = self.dns_cache.lookup(dst_ip)
        if cached_hostname:
            event = ConnectionEvent(
                type="https",
                dst_ip=dst_ip,
                dst_port=dst_port,
                host=cached_hostname,
                **proc_dict,
            )
            allowed, rule_idx = self.matcher.match(event)

            if allowed:
                return self._make_decision(
                    True,
                    rule_idx,
                    f"Matched rule {rule_idx} via DNS cache",
                    hostname=cached_hostname,
                )

        # No SNI and no DNS cache hit - try IP-based rules only
        event = ConnectionEvent(
            type="https",
            dst_ip=dst_ip,
            dst_port=dst_port,
            **proc_dict,
        )
        allowed, rule_idx = self.matcher.match(event)

        if allowed:
            return self._make_decision(True, rule_idx, f"Matched IP rule {rule_idx}")
        else:
            return self._make_decision(
                False, None, f"No rule matches {dst_ip}:{dst_port} (no SNI)"
            )

    def check_http(
        self,
        dst_ip: str,
        dst_port: int,
        url: str,
        method: str,
        proc: ProcessInfo | None = None,
    ) -> Decision:
        """Check an HTTP request.

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            url: Full request URL
            method: HTTP method (GET, POST, etc.)
            proc: Process information

        Returns:
            Decision with verdict and reason
        """
        proc_dict = proc.to_dict() if proc else {}

        # Extract hostname from URL for decision metadata
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname

        event = ConnectionEvent(
            type="http",
            dst_ip=dst_ip,
            dst_port=dst_port,
            url=url,
            method=method,
            **proc_dict,
        )
        allowed, rule_idx = self.matcher.match(event)

        if allowed:
            return self._make_decision(
                True, rule_idx, f"Matched rule {rule_idx}", hostname=hostname
            )
        else:
            return self._make_decision(
                False, None, f"No rule matches {method} {url}", hostname=hostname
            )

    def check_tcp(
        self,
        dst_ip: str,
        dst_port: int,
        proc: ProcessInfo | None = None,
    ) -> Decision:
        """Check a raw TCP connection (non-HTTP).

        Since raw TCP doesn't have hostname information, we:
        1. Try to find hostname from DNS cache
        2. Fall back to IP/CIDR rules only

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            proc: Process information

        Returns:
            Decision with verdict and reason
        """
        proc_dict = proc.to_dict() if proc else {}

        # Try DNS cache lookup first
        cached_hostname = self.dns_cache.lookup(dst_ip)
        if cached_hostname:
            # Create event with cached hostname
            event = ConnectionEvent(
                type="tcp",
                dst_ip=dst_ip,
                dst_port=dst_port,
                host=cached_hostname,
                **proc_dict,
            )
            allowed, rule_idx = self.matcher.match(event)

            if allowed:
                return self._make_decision(
                    True,
                    rule_idx,
                    f"Matched rule {rule_idx} via DNS cache ({cached_hostname})",
                    hostname=cached_hostname,
                )

        # No DNS cache hit or no match with hostname - try IP-based rules
        event = ConnectionEvent(
            type="tcp",
            dst_ip=dst_ip,
            dst_port=dst_port,
            **proc_dict,
        )
        allowed, rule_idx = self.matcher.match(event)

        if allowed:
            return self._make_decision(True, rule_idx, f"Matched IP rule {rule_idx}")
        else:
            if cached_hostname:
                return self._make_decision(
                    False,
                    None,
                    f"No rule matches tcp://{cached_hostname}:{dst_port} ({dst_ip})",
                    hostname=cached_hostname,
                )
            else:
                return self._make_decision(
                    False,
                    None,
                    f"No rule matches tcp://{dst_ip}:{dst_port} (no DNS correlation)",
                )

    def check_dns(
        self,
        dst_ip: str,
        dst_port: int,
        query_name: str,
        proc: ProcessInfo | None = None,
    ) -> Decision:
        """Check a DNS query.

        DNS queries are matched against hostname rules using the query name.

        Args:
            dst_ip: DNS server IP
            dst_port: DNS server port
            query_name: The domain being queried
            proc: Process information

        Returns:
            Decision with verdict and reason
        """
        proc_dict = proc.to_dict() if proc else {}

        event = ConnectionEvent(
            type="dns",
            dst_ip=dst_ip,
            dst_port=dst_port,
            name=query_name,
            **proc_dict,
        )
        allowed, rule_idx = self.matcher.match(event)

        if allowed:
            return self._make_decision(
                True, rule_idx, f"Matched rule {rule_idx}", hostname=query_name
            )
        else:
            return self._make_decision(
                False, None, f"No rule matches DNS query for {query_name}"
            )

    def check_udp(
        self,
        dst_ip: str,
        dst_port: int,
        proc: ProcessInfo | None = None,
    ) -> Decision:
        """Check a UDP packet (non-DNS).

        UDP packets can only match IP/CIDR rules since there's no
        hostname information available.

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            proc: Process information

        Returns:
            Decision with verdict and reason
        """
        proc_dict = proc.to_dict() if proc else {}

        event = ConnectionEvent(
            type="udp",
            dst_ip=dst_ip,
            dst_port=dst_port,
            **proc_dict,
        )
        allowed, rule_idx = self.matcher.match(event)

        if allowed:
            return self._make_decision(True, rule_idx, f"Matched rule {rule_idx}")
        else:
            return self._make_decision(
                False, None, f"No rule matches udp://{dst_ip}:{dst_port}"
            )

    def record_dns_response(self, query_name: str, ips: list[str], ttl: int) -> None:
        """Record DNS response for IP correlation.

        Called when a DNS response is received to cache the IP->hostname
        mapping for later TCP/UDP connection correlation.

        Args:
            query_name: The queried hostname
            ips: List of resolved IP addresses (A/AAAA records)
            ttl: DNS TTL in seconds
        """
        if ips:
            self.dns_cache.add_many(ips, query_name, ttl)

    @classmethod
    def for_runner(
        cls,
        policy_text: str,
        dns_cache: DNSIPCache | None = None,
        audit_mode: bool = False,
        include_defaults: bool = True,
        github_repository: str | None = None,
    ) -> "PolicyEnforcer":
        """Create an enforcer configured for GitHub Actions runner.

        This factory method creates an enforcer with the runner cgroup
        constraint applied to all rules, ensuring policies only match
        connections from the runner process tree.

        Args:
            policy_text: The policy text to parse.
            dns_cache: DNS IP cache for hostname correlation (optional).
            audit_mode: If True, log but don't block (always allow).
            include_defaults: If True, prepend GitHub Actions infrastructure defaults.
            github_repository: Value of GITHUB_REPOSITORY env var (format: "owner/repo").
                Used to substitute {owner} and {repo} placeholders in policy.

        Returns:
            PolicyEnforcer configured with runner defaults.
        """
        # Substitute {owner} and {repo} placeholders
        owner, repo = parse_github_repository(github_repository)
        policy_text = substitute_placeholders(policy_text, owner=owner, repo=repo)

        if include_defaults:
            policy_text = get_defaults() + "\n" + policy_text
        matcher = PolicyMatcher(policy_text, defaults=RUNNER_DEFAULTS)
        return cls(matcher, dns_cache, audit_mode)
