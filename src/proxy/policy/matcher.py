"""Connection matching engine - matches connection events against policy rules."""

import fnmatch
import re
import socket
import struct
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .parser import parse_policy
from .types import AttrValue, DefaultContext, Rule


@dataclass
class ConnectionEvent:
    """A connection event from the proxy log."""

    type: str  # "http", "https", "tcp", "dns", "udp"
    dst_ip: str
    dst_port: int
    url: str | None = None  # For http type
    host: str | None = None  # For https type (SNI)
    name: str | None = None  # For dns type (query name)
    method: str | None = None  # HTTP method
    exe: str | None = None
    cmdline: list[str] | None = None
    cgroup: str | None = None
    step: str | None = None
    action: str | None = None  # GitHub Action repository (e.g., "actions/checkout")

    @classmethod
    def from_dict(cls, data: dict) -> "ConnectionEvent":
        """Create a ConnectionEvent from a dictionary."""
        return cls(
            type=data.get("type", ""),
            dst_ip=data.get("dst_ip", ""),
            dst_port=data.get("dst_port", 0),
            url=data.get("url"),
            host=data.get("host"),
            name=data.get("name"),
            method=data.get("method"),
            exe=data.get("exe"),
            cmdline=data.get("cmdline"),
            cgroup=data.get("cgroup"),
            step=data.get("step"),
            action=data.get("action"),
        )


def ip_to_int(ip: str) -> int:
    """Convert an IPv4 address to an integer."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def cidr_contains(cidr: str, ip: str) -> bool:
    """Check if an IP address is within a CIDR block."""
    network, prefix_len = cidr.split("/")
    prefix_len = int(prefix_len)

    network_int = ip_to_int(network)
    ip_int = ip_to_int(ip)

    # Create mask
    mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF

    return (network_int & mask) == (ip_int & mask)


def match_hostname(pattern: str, hostname: str, is_wildcard: bool = False) -> bool:
    """Match a hostname against a pattern.

    Hostnames are case-insensitive per DNS spec.
    For wildcard patterns (*.example.com), matches any subdomain.
    """
    pattern = pattern.lower()
    hostname = hostname.lower()

    if is_wildcard:
        # Wildcard matches any subdomain(s) but not the root domain
        if hostname == pattern:
            return False  # *.example.com does not match example.com
        return hostname.endswith("." + pattern)
    else:
        return hostname == pattern


def match_url_path(pattern_path: str, actual_path: str) -> bool:
    """Match a URL path against a pattern with wildcards.

    Wildcards:
    - '*' at end of path: matches any remaining path (greedy)
    - '*' elsewhere: matches exactly one path segment
    - 'v*' partial segment: matches using fnmatch
    """
    # Normalize paths
    pattern_path = pattern_path.rstrip("/") if pattern_path != "/" else "/"
    actual_path = actual_path.rstrip("/") if actual_path != "/" else "/"

    # Split into segments
    pattern_parts = pattern_path.split("/")
    actual_parts = actual_path.split("/")

    # Check if pattern ends with trailing wildcard
    trailing_wildcard = pattern_parts and pattern_parts[-1] == "*"
    if trailing_wildcard:
        pattern_parts = pattern_parts[:-1]

    # Match segment by segment
    if not trailing_wildcard and len(pattern_parts) != len(actual_parts):
        return False

    if trailing_wildcard and len(actual_parts) < len(pattern_parts):
        return False

    for i, pattern_seg in enumerate(pattern_parts):
        if i >= len(actual_parts):
            return False

        actual_seg = actual_parts[i]

        if pattern_seg == "*":
            # Matches exactly one segment
            continue
        elif "*" in pattern_seg:
            # Partial wildcard - use fnmatch
            if not fnmatch.fnmatch(actual_seg, pattern_seg):
                return False
        else:
            # Exact match (case-sensitive for paths)
            if pattern_seg != actual_seg:
                return False

    return True


def match_port(rule_port: list[int] | str, actual_port: int) -> bool:
    """Match a port against a rule port specification."""
    if rule_port == "*":
        return True
    if isinstance(rule_port, list):
        return actual_port in rule_port
    return False


def match_protocol(rule_protocol: str, event_type: str) -> bool:
    """Match protocol based on event type.

    Event types: http, https, tcp, dns, udp
    Rule protocols: tcp, udp
    """
    if rule_protocol == "tcp":
        return event_type in ("http", "https", "tcp")
    elif rule_protocol == "udp":
        return event_type in ("dns", "udp")
    return False


def match_method(rule_methods: list[str] | None, actual_method: str | None) -> bool:
    """Match HTTP method against rule methods."""
    if rule_methods is None:
        # Non-HTTP rule - always matches
        return True

    if actual_method is None:
        # HTTP rule but no method in event - treat as GET for compatibility
        actual_method = "GET"

    actual_method = actual_method.upper()

    if "*" in rule_methods:
        return True

    return actual_method in rule_methods


def match_wildcard(pattern: str, value: str) -> bool:
    """Match a value against a pattern with wildcards using fnmatch."""
    return fnmatch.fnmatch(value, pattern)


def match_attr_value(rule_value: str | AttrValue, actual_value: str) -> bool:
    """Match an attribute value (may be literal or wildcard pattern)."""
    if isinstance(rule_value, AttrValue):
        if rule_value.literal:
            return rule_value.value == actual_value
        else:
            return match_wildcard(rule_value.value, actual_value)
    else:
        # String value - wildcards active
        return match_wildcard(rule_value, actual_value)


def match_cgroup(pattern: str, cgroup: str) -> bool:
    """Match a cgroup against a pattern.

    Supports abstractions like @docker.
    """
    if pattern == "@docker":
        # Match Docker containers
        return "docker" in cgroup.lower()
    elif pattern == "@host":
        # Match host processes (not in containers)
        return "docker" not in cgroup.lower()
    else:
        # Pattern match
        return match_wildcard(pattern, cgroup)


def match_attrs(rule: Rule, event: ConnectionEvent) -> bool:
    """Match all rule attributes against event."""
    for key, value in rule.attrs.items():
        # Handle indexed arg attributes
        if key.startswith("arg["):
            # Extract index
            idx_match = re.match(r"arg\[(\d+)\]", key)
            if idx_match:
                idx = int(idx_match.group(1))
                if event.cmdline is None or idx >= len(event.cmdline):
                    return False
                if not match_attr_value(value, event.cmdline[idx]):
                    return False
            continue

        # Handle non-indexed arg (match any argument)
        if key == "arg":
            if event.cmdline is None:
                return False
            matched = False
            for arg in event.cmdline:
                if match_attr_value(value, arg):
                    matched = True
                    break
            if not matched:
                return False
            continue

        # Handle exe
        if key == "exe":
            if event.exe is None:
                return False
            if not match_attr_value(value, event.exe):
                return False
            continue

        # Handle step
        if key == "step":
            if event.step is None:
                return False
            if not match_attr_value(value, event.step):
                return False
            continue

        # Handle action (GitHub Action repository, e.g., "actions/checkout")
        if key == "action":
            if event.action is None:
                return False
            if not match_attr_value(value, event.action):
                return False
            continue

        # Handle cgroup
        if key == "cgroup":
            if event.cgroup is None:
                return False
            pattern = value.value if isinstance(value, AttrValue) else value
            if not match_cgroup(pattern, event.cgroup):
                return False
            continue

    return True


def get_event_hostname(event: ConnectionEvent) -> str | None:
    """Extract the hostname from an event."""
    if event.host:
        return event.host
    if event.name:
        return event.name
    if event.url:
        parsed = urlparse(event.url)
        return parsed.hostname
    return None


def match_dns_name_against_rule(rule: Rule, name: str, event: ConnectionEvent) -> bool:
    """Check if a DNS query name matches a rule's hostname target.

    This allows hostname/URL rules to implicitly allow DNS resolution.
    For example, allowing "github.com" also allows DNS queries for "github.com".

    Only checks hostname matching and attributes - ignores port/protocol
    since DNS resolution is independent of the eventual connection port.
    """
    # Extract hostname from rule based on rule type
    if rule.type == "host":
        if not match_hostname(rule.target, name, is_wildcard=False):
            return False
    elif rule.type == "wildcard_host":
        if not match_hostname(rule.target, name, is_wildcard=True):
            return False
    elif rule.type == "url" or rule.type == "path":
        # Extract hostname from URL rule
        if rule.type == "url":
            parsed = urlparse(rule.target)
        else:
            # Path rule - use url_base
            if not rule.url_base:
                return False
            parsed = urlparse(rule.url_base)
        rule_hostname = parsed.hostname
        if not rule_hostname:
            return False
        if rule_hostname.lower() != name.lower():
            return False
    else:
        # IP/CIDR rules don't implicitly allow DNS
        return False

    # Check attributes (exe, cgroup, etc.) still apply
    if not match_attrs(rule, event):
        return False

    return True


def match_rule(rule: Rule, event: ConnectionEvent) -> bool:
    """Check if an event matches a rule.

    All parts of a rule must match (AND semantics within a rule).
    """
    # Check protocol first
    if not match_protocol(rule.protocol, event.type):
        return False

    # Check port
    if not match_port(rule.port, event.dst_port):
        return False

    # Check target based on rule type
    if rule.type == "ip":
        if event.dst_ip != rule.target:
            return False

    elif rule.type == "cidr":
        if not cidr_contains(rule.target, event.dst_ip):
            return False

    elif rule.type == "host":
        hostname = get_event_hostname(event)
        if hostname is None:
            # No hostname in event - host rules require hostname to match
            return False
        if not match_hostname(rule.target, hostname, is_wildcard=False):
            return False

    elif rule.type == "wildcard_host":
        hostname = get_event_hostname(event)
        if hostname is None:
            return False
        if not match_hostname(rule.target, hostname, is_wildcard=True):
            return False

    elif rule.type == "url":
        if event.url is None:
            return False
        # Parse the rule URL and event URL
        rule_parsed = urlparse(rule.target)
        event_parsed = urlparse(event.url)

        # Match scheme
        if rule_parsed.scheme != event_parsed.scheme:
            return False

        # Match host (case-insensitive)
        if rule_parsed.hostname and event_parsed.hostname:
            if rule_parsed.hostname.lower() != event_parsed.hostname.lower():
                return False

        # Match path
        rule_path = rule_parsed.path or "/"
        event_path = event_parsed.path or "/"
        if not match_url_path(rule_path, event_path):
            return False

        # Match method
        if not match_method(rule.methods, event.method):
            return False

    elif rule.type == "path":
        if event.url is None:
            return False
        if rule.url_base is None:
            return False

        # Construct full URL from base and path
        base_parsed = urlparse(rule.url_base)
        event_parsed = urlparse(event.url)

        # Match scheme and host from base
        if base_parsed.scheme != event_parsed.scheme:
            return False
        if base_parsed.hostname and event_parsed.hostname:
            if base_parsed.hostname.lower() != event_parsed.hostname.lower():
                return False

        # Construct expected path
        base_path = base_parsed.path.rstrip("/") if base_parsed.path else ""
        rule_path = rule.target
        # Combine base path and rule path
        if base_path and rule_path.startswith("/"):
            full_pattern_path = base_path + rule_path
        else:
            full_pattern_path = base_path + rule_path

        # Normalize double slashes
        full_pattern_path = re.sub(r"//+", "/", full_pattern_path)

        event_path = event_parsed.path or "/"
        if not match_url_path(full_pattern_path, event_path):
            return False

        # Match method
        if not match_method(rule.methods, event.method):
            return False

    # Check attributes
    if not match_attrs(rule, event):
        return False

    return True


class PolicyMatcher:
    """Matches connection events against a policy."""

    def __init__(self, policy_text: str, defaults: DefaultContext | None = None):
        """Initialize with a policy text.

        Args:
            policy_text: The policy text to parse.
            defaults: Optional DefaultContext to override security defaults.
        """
        self.rules = parse_policy(policy_text, defaults=defaults)

    def match(self, event: ConnectionEvent | dict) -> tuple[bool, int | None]:
        """Check if an event is allowed by the policy.

        Returns (allowed, matching_rule_index).
        If blocked, matching_rule_index is None.
        """
        if isinstance(event, dict):
            event = ConnectionEvent.from_dict(event)

        # DNS queries require BOTH resolver and domain to be allowed
        if event.type == "dns" and event.name:
            return self._match_dns(event)

        for i, rule in enumerate(self.rules):
            if match_rule(rule, event):
                return (True, i)

        return (False, None)

    def _match_dns(self, event: ConnectionEvent) -> tuple[bool, int | None]:
        """Match DNS queries with dual check: resolver + domain.

        DNS is allowed only if:
        1. The DNS server (IP/port) is allowed by an IP/CIDR rule
        2. The queried domain is allowed by a hostname/URL rule

        This prevents:
        - Resolving arbitrary domains on allowed resolvers
        - Using arbitrary resolvers for allowed domains
        """
        # Check 1: Is the resolver allowed? (IP/CIDR rules with UDP protocol)
        resolver_allowed = False
        for rule in self.rules:
            if rule.type in ("ip", "cidr") and rule.protocol == "udp":
                if match_port(rule.port, event.dst_port):
                    if rule.type == "ip" and event.dst_ip == rule.target:
                        if match_attrs(rule, event):
                            resolver_allowed = True
                            break
                    elif rule.type == "cidr" and cidr_contains(
                        rule.target, event.dst_ip
                    ):
                        if match_attrs(rule, event):
                            resolver_allowed = True
                            break

        if not resolver_allowed:
            return (False, None)

        # Check 2: Is the domain allowed? (hostname/URL rules)
        for i, rule in enumerate(self.rules):
            if match_dns_name_against_rule(rule, event.name, event):
                return (True, i)

        return (False, None)

    def verdict(self, event: ConnectionEvent | dict) -> str:
        """Get verdict for an event: 'allow' or 'block'."""
        allowed, _ = self.match(event)
        return "allow" if allowed else "block"
