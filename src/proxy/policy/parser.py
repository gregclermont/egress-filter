"""Policy parser - converts policy text to flattened rules."""

import re
from typing import Iterator

from .types import AttrValue, HeaderContext, Protocol, Rule

# =============================================================================
# Regex patterns
# =============================================================================

# IPv4 components
OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
IPV4 = rf"(?:{OCTET}\.{OCTET}\.{OCTET}\.{OCTET})"

# Patterns for rule types
IP_PATTERN = re.compile(rf"^({IPV4})$")
CIDR_PATTERN = re.compile(rf"^({IPV4}/(?:3[0-2]|[12]?[0-9]))$")
WILDCARD_HOST_PATTERN = re.compile(r"^\*\.(.+)$")
URL_PATTERN = re.compile(r"^(https?://[^\s]+)$")
PATH_PATTERN = re.compile(r"^(/[^\s]*)$")

# Hostname validation (simplified - allows valid DNS names)
# TLD must start with a letter to distinguish from invalid IPs like 256.0.0.0
HOSTNAME_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$"
)
TLD_STARTS_WITH_LETTER = re.compile(r"\.[a-zA-Z][a-zA-Z0-9]*$")

# Port pattern: :PORT or :PORT|PORT or :*
PORT_PATTERN = re.compile(r"^:(\*|\d+(?:\|\d+)*)$")

# Protocol pattern: /tcp or /udp
PROTO_PATTERN = re.compile(r"^/(tcp|udp)$")

# HTTP methods
METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "*"}
METHOD_PATTERN = re.compile(r"^([A-Z*]+(?:\|[A-Z*]+)*)$")

# Attribute patterns
ATTR_PATTERN = re.compile(r"^([a-z]+(?:\[\d+\])?)=(.+)$")
QUOTED_VALUE = re.compile(r'^"([^"]*)"$')
BACKTICK_VALUE = re.compile(r"^`([^`]*)`$")

# Header pattern: [content] or []
HEADER_PATTERN = re.compile(r"^\s*\[(.*)\]\s*(?:#.*)?$")

# Comment pattern
COMMENT_PATTERN = re.compile(r"#.*$")


def is_valid_hostname(hostname: str) -> bool:
    """Check if a string is a valid hostname.

    Requirements:
    - Matches DNS name pattern
    - TLD must start with a letter (to reject things like 256.0.0.0)
    """
    if not HOSTNAME_PATTERN.match(hostname):
        return False
    # TLD must start with a letter
    if not TLD_STARTS_WITH_LETTER.search(hostname):
        return False
    return True


def validate_url(url: str) -> str | None:
    """Validate a URL for policy rules.

    Returns None if invalid, otherwise returns the validated URL.

    Rejects:
    - Query strings (?...)
    - Fragments (#...)
    - Wildcards in hostname (*.example.com)
    """
    # Check for query string or fragment
    if "?" in url or "#" in url.split("://", 1)[-1]:
        return None

    # Extract hostname from URL
    try:
        url_no_scheme = url.split("://", 1)[1]
        host_part = url_no_scheme.split("/")[0]
        # Remove port if present
        if ":" in host_part:
            hostname = host_part.rsplit(":", 1)[0]
        else:
            hostname = host_part

        # Reject wildcards in URL hostname
        if "*" in hostname:
            return None

    except (IndexError, ValueError):
        return None

    return url


def parse_port_proto(text: str) -> tuple[list[int] | str | None, Protocol | None]:
    """Parse port and protocol suffix like ':443/tcp' or ':53/udp' or ':*'.

    Returns (port, protocol) where each can be None if not specified.
    """
    port: list[int] | str | None = None
    protocol: Protocol | None = None

    # Check for protocol suffix first
    if "/udp" in text:
        protocol = "udp"
        text = text.replace("/udp", "")
    elif "/tcp" in text:
        protocol = "tcp"
        text = text.replace("/tcp", "")

    # Check for port
    if ":" in text:
        port_match = PORT_PATTERN.match(text[text.rindex(":") :])
        if port_match:
            port_str = port_match.group(1)
            if port_str == "*":
                port = "*"
            else:
                port = [int(p) for p in port_str.split("|")]

    return port, protocol


def parse_methods(text: str) -> list[str] | None:
    """Parse method prefix like 'GET' or 'GET|POST'.

    Returns list of methods or None if no methods specified.
    """
    match = METHOD_PATTERN.match(text)
    if match:
        methods = match.group(1).split("|")
        if all(m in METHODS for m in methods):
            return methods
    return None


def parse_attrs(parts: list[str]) -> dict[str, str | AttrValue]:
    """Parse key=value attributes from remaining parts."""
    attrs: dict[str, str | AttrValue] = {}

    for part in parts:
        match = ATTR_PATTERN.match(part)
        if match:
            key, value = match.groups()

            # Check for quoted value (literal, no wildcards)
            quoted = QUOTED_VALUE.match(value)
            if quoted:
                attrs[key] = AttrValue(value=quoted.group(1), literal=True)
                continue

            # Check for backtick value (wildcards active)
            backtick = BACKTICK_VALUE.match(value)
            if backtick:
                attrs[key] = AttrValue(value=backtick.group(1), literal=False)
                continue

            # Unquoted value (wildcards active)
            attrs[key] = value

    return attrs


def parse_header(content: str, ctx: HeaderContext) -> None:
    """Parse header content and update context.

    Headers can contain:
    - Port: :443, :80|443, :*
    - Protocol: :53/udp
    - Methods: GET, GET|HEAD
    - URL base: https://api.github.com, https://api.github.com/v1
    - Empty: [] resets to defaults

    Each header is a full reset - it doesn't accumulate with previous headers.
    """
    content = content.strip()

    # Empty header resets to defaults
    if not content:
        ctx.reset()
        return

    # Check for URL base
    if content.startswith("http://") or content.startswith("https://"):
        # Reset context first, then set URL base
        ctx.reset()
        ctx.url_base = content
        # Extract port from URL if present
        url_no_scheme = content.split("://", 1)[1]
        if ":" in url_no_scheme.split("/")[0]:
            # Has explicit port in URL
            host_port = url_no_scheme.split("/")[0]
            port_str = host_port.split(":")[-1]
            try:
                ctx.port = [int(port_str)]
            except ValueError:
                pass
        else:
            # Default port based on scheme
            ctx.port = [443] if content.startswith("https://") else [80]
        ctx.protocol = "tcp"
        return

    # Check for methods only
    methods = parse_methods(content)
    if methods:
        # Reset context first, then set methods
        ctx.reset()
        ctx.methods = methods
        return

    # Check for port/protocol
    if content.startswith(":"):
        # Reset context first, then set port/protocol
        ctx.reset()
        port, protocol = parse_port_proto(content)
        if port is not None:
            ctx.port = port
        if protocol is not None:
            ctx.protocol = protocol
        return


def tokenize_line(line: str) -> list[str]:
    """Tokenize a line respecting quoted and backtick strings.

    Handles:
    - Unquoted tokens (space-separated)
    - "double quoted" values (spaces preserved)
    - `backtick quoted` values (spaces preserved)
    """
    tokens = []
    i = 0
    current = ""

    while i < len(line):
        char = line[i]

        if char in " \t":
            # Whitespace - end current token
            if current:
                tokens.append(current)
                current = ""
            i += 1
        elif char == '"':
            # Double-quoted string
            current += char
            i += 1
            while i < len(line) and line[i] != '"':
                current += line[i]
                i += 1
            if i < len(line):
                current += line[i]  # Include closing quote
                i += 1
        elif char == "`":
            # Backtick-quoted string
            current += char
            i += 1
            while i < len(line) and line[i] != "`":
                current += line[i]
                i += 1
            if i < len(line):
                current += line[i]  # Include closing backtick
                i += 1
        else:
            current += char
            i += 1

    if current:
        tokens.append(current)

    return tokens


def parse_rule_line(line: str, ctx: HeaderContext) -> Rule | None:
    """Parse a single rule line using current context.

    Returns a Rule or None if the line is not a valid rule.
    """
    line = line.strip()

    # Skip empty lines and comments
    if not line or line.startswith("#"):
        return None

    # Strip inline comments (but not inside quotes)
    # Simple approach: find # that's not inside quotes
    # Note: For URLs, # could be a fragment - reject those in validate_url
    in_quote = None
    comment_idx = -1
    for i, char in enumerate(line):
        if in_quote:
            if char == in_quote:
                in_quote = None
        elif char in ('"', "`"):
            in_quote = char
        elif char == "#":
            # Check if this looks like a URL fragment (# immediately after path chars)
            # If line starts with http:// or https://, and # is before any space,
            # it's likely a fragment, not a comment - reject the whole line
            if (
                line.startswith("http://") or line.startswith("https://")
            ) and " " not in line[:i]:
                return None  # URL with fragment - invalid
            comment_idx = i
            break
    if comment_idx >= 0:
        line = line[:comment_idx].strip()
    if not line:
        return None

    # Tokenize respecting quotes
    parts = tokenize_line(line)
    if not parts:
        return None

    # Check for method prefix
    methods: list[str] | None = None
    if len(parts) >= 2:
        maybe_methods = parse_methods(parts[0])
        if maybe_methods:
            methods = maybe_methods
            parts = parts[1:]

    if not parts:
        return None

    # First part is the target (possibly with port/protocol suffix)
    target_part = parts[0]
    remaining_parts = parts[1:]

    # Parse port/protocol from target or remaining parts
    port: list[int] | str | None = None
    protocol: Protocol | None = None

    # Check if target has port/protocol suffix
    if ":" in target_part or "/udp" in target_part or "/tcp" in target_part:
        # Extract the base target and port/protocol
        base_target = target_part

        # Handle protocol suffix - /udp and /tcp require explicit port
        if "/udp" in base_target:
            # Check that there's a port before /udp
            if ":" not in base_target.split("/udp")[0]:
                return None  # /udp without port is invalid
            protocol = "udp"
            base_target = base_target.replace("/udp", "")
        elif "/tcp" in base_target:
            # /tcp is optional but if present, must have port
            if ":" not in base_target.split("/tcp")[0]:
                return None  # /tcp without port is invalid
            protocol = "tcp"
            base_target = base_target.replace("/tcp", "")

        # Handle port
        if ":" in base_target and not base_target.startswith("http"):
            colon_idx = base_target.rfind(":")
            port_str = base_target[colon_idx + 1 :]
            base_target = base_target[:colon_idx]
            if port_str == "*":
                port = "*"
            elif port_str:
                try:
                    port = [int(p) for p in port_str.split("|")]
                except ValueError:
                    pass

        target_part = base_target

    # Check remaining parts for port/protocol attributes
    new_remaining = []
    for part in remaining_parts:
        if part.startswith(":"):
            p, pr = parse_port_proto(part)
            if p is not None:
                port = p
            if pr is not None:
                protocol = pr
        elif part.startswith("/") and part in ("/tcp", "/udp"):
            protocol = "tcp" if part == "/tcp" else "udp"
        else:
            new_remaining.append(part)
    remaining_parts = new_remaining

    # Parse attributes
    attrs = parse_attrs(remaining_parts)

    # Apply context defaults
    if port is None:
        port = ctx.port
    if protocol is None:
        protocol = ctx.protocol

    # Determine rule type and create rule
    rule_type = None
    target = target_part

    # Check for path rule
    if target.startswith("/"):
        if ctx.url_base is None:
            # Path rule without URL base context - invalid
            return None
        rule_type = "path"
        if methods is None:
            methods = ctx.methods if ctx.methods else ["GET", "HEAD"]
        return Rule(
            type=rule_type,
            target=target,
            port=port,
            protocol=protocol,
            methods=methods,
            url_base=ctx.url_base,
            attrs=attrs,
        )

    # Check for URL rule
    if target.startswith("http://") or target.startswith("https://"):
        # Validate URL (rejects query strings, wildcards in hostname)
        if validate_url(target) is None:
            return None

        rule_type = "url"
        # Parse port from URL if not already set from suffix
        if port == ctx.port:  # Not overridden
            if "://" in target:
                url_no_scheme = target.split("://", 1)[1]
                host_part = url_no_scheme.split("/")[0]
                if ":" in host_part:
                    port_str = host_part.split(":")[-1]
                    try:
                        port = [int(port_str)]
                    except ValueError:
                        pass
                else:
                    port = [443] if target.startswith("https://") else [80]
        if methods is None:
            methods = ctx.methods if ctx.methods else ["GET", "HEAD"]
        return Rule(
            type=rule_type,
            target=target,
            port=port,
            protocol=protocol,
            methods=methods,
            url_base=None,
            attrs=attrs,
        )

    # Check for CIDR
    if CIDR_PATTERN.match(target):
        rule_type = "cidr"
        return Rule(
            type=rule_type,
            target=target,
            port=port,
            protocol=protocol,
            methods=None,
            url_base=None,
            attrs=attrs,
        )

    # Check for IP
    if IP_PATTERN.match(target):
        rule_type = "ip"
        return Rule(
            type=rule_type,
            target=target,
            port=port,
            protocol=protocol,
            methods=None,
            url_base=None,
            attrs=attrs,
        )

    # Check for wildcard hostname
    wildcard_match = WILDCARD_HOST_PATTERN.match(target)
    if wildcard_match:
        wildcard_domain = wildcard_match.group(1)
        # Validate the domain part (TLD must start with letter)
        if not is_valid_hostname(wildcard_domain):
            return None
        rule_type = "wildcard_host"
        return Rule(
            type=rule_type,
            target=wildcard_domain,  # Store without *. prefix
            port=port,
            protocol=protocol,
            methods=None,
            url_base=None,
            attrs=attrs,
        )

    # Validate hostname (TLD must start with letter)
    if not is_valid_hostname(target):
        return None

    rule_type = "host"
    return Rule(
        type=rule_type,
        target=target,
        port=port,
        protocol=protocol,
        methods=None,
        url_base=None,
        attrs=attrs,
    )


def parse_policy(policy_text: str) -> list[Rule]:
    """Parse a policy text into a list of flattened rules.

    Headers set context for subsequent rules. Each rule is self-sufficient
    after parsing (context is inlined into the rule).
    """
    rules: list[Rule] = []
    ctx = HeaderContext()

    for line in policy_text.splitlines():
        line = line.strip()

        # Skip empty lines and comment-only lines
        if not line or line.startswith("#"):
            continue

        # Check for header
        header_match = HEADER_PATTERN.match(line)
        if header_match:
            parse_header(header_match.group(1), ctx)
            continue

        # Parse as rule
        rule = parse_rule_line(line, ctx)
        if rule:
            rules.append(rule)

    return rules


def flatten_policy(policy_text: str) -> Iterator[dict]:
    """Parse policy and yield flattened rule dictionaries.

    This is a convenience function for testing - converts rules to dicts
    matching the test fixture format.
    """
    for rule in parse_policy(policy_text):
        yield rule_to_dict(rule)


def rule_to_dict(rule: Rule) -> dict:
    """Convert a Rule to a dictionary matching test fixture format."""
    attrs_dict = {}
    for key, value in rule.attrs.items():
        if isinstance(value, AttrValue):
            attrs_dict[key] = {"value": value.value, "literal": value.literal}
        else:
            attrs_dict[key] = value

    return {
        "type": rule.type,
        "target": rule.target,
        "port": rule.port,
        "protocol": rule.protocol,
        "methods": rule.methods,
        "url_base": rule.url_base,
        "attrs": attrs_dict,
    }
