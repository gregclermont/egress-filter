"""Policy parser - converts policy text to flattened rules using PEG grammar.

Uses parsimonious for PEG parsing. The grammar is the source of truth for
what syntax is valid - validation happens at parse time, not after.
"""

import logging
from urllib.parse import urlparse

from parsimonious.exceptions import ParseError
from parsimonious.grammar import Grammar
from parsimonious.nodes import Node, NodeVisitor

from .types import (
    SECURE_DEFAULTS,
    AttrValue,
    DefaultContext,
    HeaderContext,
    Protocol,
    Rule,
)

logger = logging.getLogger(__name__)

# =============================================================================
# PEG Grammar (source of truth for syntax)
# =============================================================================

GRAMMAR = Grammar(r"""
policy          = (line newline)* line?
line            = header / rule / comment_only / blank
blank           = ws*
comment_only    = ws* comment
comment         = "#" ~"[^\n]*"
inline_comment  = ws+ comment
newline         = "\n" / "\r\n"
ws              = " " / "\t"

header          = ws* "[" header_content? "]" inline_comment? ws*
header_content  = passthrough_header / url_base_header / method_header / port_proto_header / kv_only_header
passthrough_header = "passthrough" kv_attrs?
url_base_header = url_base kv_attrs?
method_header   = method_attr kv_attrs?
port_proto_header = port_proto_attr kv_attrs?
kv_only_header  = kv_attr (ws+ kv_attr)*
url_base        = scheme "://" url_host url_port? url_path?
port_proto_attr = port_attr proto_attr?

rule            = ws* (url_rule / path_rule / network_rule) inline_comment? ws*

url_rule        = (method_attr ws+)? scheme "://" url_host url_port? url_path kv_attrs?
url_host        = ipv4 / hostname
scheme          = "https" / "http"
url_port        = ":" ~"[0-9]+"
url_path        = "/" path_rest
path_rest       = ~"[a-zA-Z0-9_.~*/%+-]*"

path_rule       = (method_attr ws+)? "/" path_rest kv_attrs?

network_rule    = (cidr_rule / ip_rule / dns_host_rule / host_rule) port_proto_attr? passthrough_flag? kv_attrs?
passthrough_flag = ws+ "passthrough"

dns_host_rule   = "dns:" (wildcard_host / exact_host)

host_rule       = wildcard_host / exact_host
wildcard_host   = subdomain_wildcard / label_wildcard
subdomain_wildcard = "*." wildcard_label "." hostname_or_tld
label_wildcard  = wildcard_label "." hostname_or_tld
wildcard_label  = ~"[a-zA-Z0-9-]*\\*[a-zA-Z0-9*-]*"
exact_host      = !ipv4_lookahead hostname !(":/")
hostname        = (hostname_part ".")+ tld
hostname_or_tld = hostname / tld
tld             = ~"[a-zA-Z][a-zA-Z0-9]*"
hostname_part   = ~"[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?" / ~"[a-zA-Z0-9]"

ip_rule         = ipv4 !("." / "/")
cidr_rule       = ipv4 "/" cidr_mask

ipv4            = octet "." octet "." octet "." octet !(".")
ipv4_lookahead  = ~"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"
octet           = ~"25[0-5]" / ~"2[0-4][0-9]" / ~"1[0-9][0-9]" / ~"[1-9][0-9]" / ~"[0-9]"
cidr_mask       = ~"3[0-2]" / ~"[12][0-9]" / ~"[0-9]"

kv_attrs        = (ws+ kv_attr)+
port_attr       = ":" port_list
port_list       = port_value ("|" port_value)*
port_value      = "*" / ~"[0-9]+"

proto_attr      = "/" protocol
protocol        = "udp" / "tcp"

method_attr     = method ("|" method)*
method          = "GET" / "HEAD" / "POST" / "PUT" / "DELETE" / "PATCH" / "OPTIONS" / "*"

kv_attr         = kv_key "=" kv_value
kv_key          = arg_indexed / "image" / "action" / "step" / "cgroup" / "exe" / "arg"
arg_indexed     = "arg[" ~"[0-9]+" "]"
kv_value        = backtick_value / quoted_value / unquoted_value
backtick_value  = "`" ~"[^`]*" "`"
quoted_value    = "\"" ~"[^\"]*" "\""
unquoted_value  = ~"[^\\s#\\]]+"
""")


# =============================================================================
# Helper to extract values from parse tree
# =============================================================================


def _get_text(node_or_list):
    """Extract text from a node or nested list structure."""
    if isinstance(node_or_list, Node):
        return node_or_list.text
    if isinstance(node_or_list, str):
        return node_or_list
    if isinstance(node_or_list, list):
        return "".join(_get_text(x) for x in node_or_list if x)
    raise TypeError(f"Unexpected type in parse tree: {type(node_or_list).__name__}")


def _is_empty(visited):
    """Check if visited children represent an empty/optional match."""
    assert visited is not None, "unexpected None in parse tree"
    if isinstance(visited, Node):
        return visited.text == ""
    if isinstance(visited, list):
        return len(visited) == 0 or all(_is_empty(x) for x in visited)
    return False


def _flatten(lst):
    """Flatten nested lists, filtering out empty nodes."""
    result = []
    for item in lst:
        assert item is not None, "unexpected None in parse tree"
        if isinstance(item, list):
            result.extend(_flatten(item))
        elif not _is_empty(item):
            result.append(item)
    return result


# =============================================================================
# AST Visitor - transforms parse tree to Rule objects
# =============================================================================


class PolicyVisitor(NodeVisitor):
    """Visits parse tree and extracts structured data."""

    def __init__(self, defaults: DefaultContext | None = None):
        self.rules = []
        self.warnings = []
        self._defaults = defaults or SECURE_DEFAULTS
        self.ctx = HeaderContext(
            port=list(self._defaults.port)
            if isinstance(self._defaults.port, list)
            else self._defaults.port,
            protocol=self._defaults.protocol,
            attrs=dict(self._defaults.attrs),
            _defaults=self._defaults,
        )

    def visit_policy(self, node, visited_children):
        return self.rules

    def visit_line(self, node, visited_children):
        return visited_children[0] if visited_children else None

    def visit_header(self, node, visited_children):
        # ws* "[" header_content? "]" inline_comment? ws*
        _, _, header_content, _, _, _ = visited_children

        # Reset context for new header
        self.ctx.reset()

        if not _is_empty(header_content):
            attrs = _flatten(header_content)

            # Check if the entire attrs list is a method list (e.g., [GET|HEAD] header)
            # This happens because _flatten unwraps ['GET', 'HEAD'] into individual strings
            valid_methods = (
                "GET",
                "HEAD",
                "POST",
                "PUT",
                "DELETE",
                "PATCH",
                "OPTIONS",
                "*",
            )
            if attrs and all(isinstance(x, str) and x in valid_methods for x in attrs):
                self.ctx.methods = attrs
            else:
                for attr in attrs:
                    if isinstance(attr, dict):
                        if "url_base" in attr:
                            self.ctx.url_base = attr["url_base"]
                            # Extract port from URL if present, else use scheme default
                            url_base = attr["url_base"]
                            # Check for explicit port (e.g., http://host:8080)
                            parsed = urlparse(url_base)
                            if parsed.port:
                                self.ctx.port = [parsed.port]
                            elif url_base.startswith("https://"):
                                self.ctx.port = [443]
                            else:
                                self.ctx.port = [80]
                            self.ctx.protocol = "tcp"
                        if "methods" in attr:
                            self.ctx.methods = attr["methods"]
                        if "port" in attr:
                            self.ctx.port = attr["port"]
                        if "protocol" in attr:
                            self.ctx.protocol = attr["protocol"]
                        if "passthrough" in attr:
                            self.ctx.passthrough = True
                        # Handle kv_attrs in headers (exe=, cgroup=, etc.)
                        for key in list(attr.keys()):
                            if key not in ("url_base", "methods", "port", "protocol", "passthrough"):
                                self.ctx.attrs[key] = attr[key]
        return None

    def visit_header_content(self, node, visited_children):
        return visited_children[0]

    def visit_passthrough_header(self, node, visited_children):
        # "passthrough" kv_attrs?
        _, kv_attrs = visited_children
        result = {"passthrough": True}
        if not _is_empty(kv_attrs):
            flat_kv = _flatten([kv_attrs])
            for item in flat_kv:
                if isinstance(item, dict):
                    result.update(item)
        return result

    def visit_method_header(self, node, visited_children):
        # method_attr kv_attrs?
        method_attr, kv_attrs = visited_children
        result = {}

        # Process method attr
        flat_methods = _flatten([method_attr])
        valid_methods = (
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "OPTIONS",
            "*",
        )
        method_strs = [
            x for x in flat_methods if isinstance(x, str) and x in valid_methods
        ]
        if method_strs:
            result["methods"] = method_strs

        # Process kv attrs
        if not _is_empty(kv_attrs):
            flat_kv = _flatten([kv_attrs])
            for item in flat_kv:
                if isinstance(item, dict):
                    result.update(item)

        return result

    def visit_port_proto_header(self, node, visited_children):
        # port_proto_attr kv_attrs?
        port_proto, kv_attrs = visited_children
        result = {}

        # Process port/proto
        if not _is_empty(port_proto):
            flat_pp = _flatten([port_proto])
            for item in flat_pp:
                if isinstance(item, dict):
                    result.update(item)
                elif isinstance(item, list):
                    result["port"] = item
                elif item == "*":
                    result["port"] = "*"
                elif isinstance(item, int):
                    result["port"] = [item]
                elif item in ("udp", "tcp"):
                    result["protocol"] = item

        # Process kv attrs
        if not _is_empty(kv_attrs):
            flat_kv = _flatten([kv_attrs])
            for item in flat_kv:
                if isinstance(item, dict):
                    result.update(item)

        return result

    def visit_kv_only_header(self, node, visited_children):
        # kv_attr (ws+ kv_attr)*
        result = {}
        flat = _flatten(visited_children)
        for item in flat:
            if isinstance(item, dict):
                result.update(item)
        return result

    def visit_url_base_header(self, node, visited_children):
        # url_base_header = url_base kv_attrs?
        url_base, kv_attrs = visited_children
        result = {}

        # Get URL base from nested structure
        flat_base = _flatten([url_base])
        for item in flat_base:
            if isinstance(item, dict) and "url_base" in item:
                result["url_base"] = item["url_base"]
                break

        # Process kv attrs
        if not _is_empty(kv_attrs):
            flat_kv = _flatten([kv_attrs])
            for item in flat_kv:
                if isinstance(item, dict):
                    result.update(item)

        return result

    def visit_url_base(self, node, visited_children):
        return {"url_base": node.text}

    def visit_port_proto_attr(self, node, visited_children):
        # port_attr proto_attr?
        result = {}
        flat = _flatten(visited_children)
        for item in flat:
            if isinstance(item, dict):
                result.update(item)
            elif isinstance(item, list):
                result["port"] = item
            elif item == "*":
                result["port"] = "*"
            elif isinstance(item, int):
                result["port"] = [item]
            elif item in ("udp", "tcp"):
                result["protocol"] = item
        return result if result else None

    def visit_rule(self, node, visited_children):
        # rule = ws* (url_rule / path_rule / network_rule) inline_comment? ws*
        _, rule_data, _, _ = visited_children

        # Extract rule info from nested structure
        rule_info = None
        flat_rule = _flatten([rule_data])
        for item in flat_rule:
            if isinstance(item, dict) and "type" in item:
                rule_info = item
                break

        if not rule_info:
            return None

        rule_type = rule_info.get("type")
        target = rule_info.get("target")

        # Get port/protocol - URL rules derive from scheme, others from rule or context
        if rule_type == "url":
            # Check for explicit port in URL first
            if rule_info.get("port"):
                port = rule_info["port"]
            elif target.startswith("http://"):
                port = [80]
            else:  # https://
                port = [443]
            protocol = "tcp"  # URLs are always TCP
        elif rule_type == "path":
            # Path rules inherit from URL base context
            port = self.ctx.port
            protocol = "tcp"  # URLs are always TCP
        else:
            # Network rules (ip, cidr, host) - use rule's port/proto or context
            port = rule_info.get("port", self.ctx.port)
            protocol = rule_info.get("protocol", self.ctx.protocol)

        # Extract attributes - start with context attrs, then override with rule attrs
        attrs = dict(self.ctx.attrs)  # Copy context attrs
        rule_attrs = rule_info.get("attrs", {})
        if rule_attrs:
            attrs.update(rule_attrs)

        # Build the Rule
        methods = rule_info.get("methods")
        url_base = rule_info.get("url_base")

        # Apply context defaults for methods on URL/path rules
        if rule_type in ("url", "path") and methods is None:
            methods = (
                self.ctx.methods if self.ctx.methods else list(self._defaults.methods)
            )

        # Path rules need URL base from context
        if rule_type == "path":
            url_base = self.ctx.url_base
            if url_base is None:
                # Path rule without URL context - skip
                self.warnings.append(
                    "Path rule requires a URL header context (e.g., [https://example.com])"
                )
                return None

        # Determine passthrough from rule-level flag or header context
        is_passthrough = rule_info.get("passthrough", False) or self.ctx.passthrough

        # Validate: passthrough only applies to host/wildcard_host rules
        if is_passthrough and rule_type not in ("host", "wildcard_host"):
            self.warnings.append(
                f"passthrough is only supported on hostname and wildcard rules, not {rule_type}"
            )
            logger.debug(
                "Skipping passthrough on unsupported rule type %r: %s",
                rule_type,
                target,
            )
            return None

        rule = Rule(
            type=rule_type,
            target=target,
            port=port,
            protocol=protocol,
            methods=methods,
            url_base=url_base,
            attrs=attrs,
            passthrough=is_passthrough,
        )
        self.rules.append(rule)
        return rule

    def visit_url_rule(self, node, visited_children):
        # url_rule = (method_attr ws+)? scheme "://" url_host url_port? url_path kv_attrs?
        method_part, scheme, _, url_host, url_port, url_path, kv_attrs = (
            visited_children
        )

        methods = None
        if not _is_empty(method_part):
            flat = _flatten([method_part])
            # Collect method strings from flattened list
            method_strs = [
                x
                for x in flat
                if isinstance(x, str)
                and x
                in ("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "*")
            ]
            if method_strs:
                methods = method_strs

        # Build full URL as target (without method prefix)
        scheme_text = _get_text(scheme)
        host_text = _get_text(url_host)  # Can be hostname or IP address
        port_text = _get_text(url_port)
        path_text = _get_text(url_path)

        target = f"{scheme_text}://{host_text}{port_text}{path_text}"

        # Extract explicit port if present
        port = None
        if port_text:
            port = [int(port_text[1:])]  # Strip leading ":"

        # Extract kv attrs
        attrs = {}
        if not _is_empty(kv_attrs):
            flat_attrs = _flatten([kv_attrs])
            for attr in flat_attrs:
                if isinstance(attr, dict):
                    attrs.update(attr)

        return {
            "type": "url",
            "target": target,
            "methods": methods,
            "port": port,
            "attrs": attrs,
        }

    def visit_path_rule(self, node, visited_children):
        # path_rule = (method_attr ws+)? "/" path_rest kv_attrs?
        method_part, slash, path_rest, kv_attrs = visited_children

        methods = None
        if not _is_empty(method_part):
            flat = _flatten([method_part])
            # Collect method strings from flattened list
            method_strs = [
                x
                for x in flat
                if isinstance(x, str)
                and x
                in ("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "*")
            ]
            if method_strs:
                methods = method_strs

        target = "/" + _get_text(path_rest)

        # Extract kv attrs
        attrs = {}
        if not _is_empty(kv_attrs):
            flat_attrs = _flatten([kv_attrs])
            for attr in flat_attrs:
                if isinstance(attr, dict):
                    attrs.update(attr)

        return {
            "type": "path",
            "target": target,
            "methods": methods,
            "url_base": None,
            "attrs": attrs,
        }

    def visit_passthrough_flag(self, node, visited_children):
        return {"passthrough": True}

    def visit_network_rule(self, node, visited_children):
        # network_rule = (cidr_rule / ip_rule / dns_host_rule / host_rule) port_proto_attr? passthrough_flag? kv_attrs?
        rule_data, port_proto, passthrough_flag, kv_attrs = visited_children

        # Extract base rule info
        rule_info = None
        flat_rule = _flatten([rule_data])
        for item in flat_rule:
            if isinstance(item, dict) and "type" in item:
                rule_info = dict(item)  # Copy so we can modify
                break

        if not rule_info:
            return None

        # Apply port/proto if present
        if not _is_empty(port_proto):
            flat_pp = _flatten([port_proto])
            for item in flat_pp:
                if isinstance(item, dict):
                    if "port" in item:
                        rule_info["port"] = item["port"]
                    if "protocol" in item:
                        rule_info["protocol"] = item["protocol"]

        # Apply passthrough flag
        if not _is_empty(passthrough_flag):
            flat_pt = _flatten([passthrough_flag])
            for item in flat_pt:
                if isinstance(item, dict) and "passthrough" in item:
                    rule_info["passthrough"] = True

        # Apply kv attrs
        attrs = {}
        if not _is_empty(kv_attrs):
            flat_attrs = _flatten([kv_attrs])
            for attr in flat_attrs:
                if isinstance(attr, dict):
                    attrs.update(attr)
        if attrs:
            rule_info["attrs"] = attrs

        return rule_info

    def visit_host_rule(self, node, visited_children):
        flat = _flatten(visited_children)
        for item in flat:
            if isinstance(item, dict):
                return item
        return None

    def visit_dns_host_rule(self, node, visited_children):
        # "dns:" (wildcard_host / exact_host)
        # The child returns {"type": "host" or "wildcard_host", "target": ...}
        # We need to transform to dns_host or dns_wildcard_host
        _, host_data = visited_children
        flat = _flatten([host_data])
        for item in flat:
            if isinstance(item, dict) and "type" in item:
                # Transform type to dns_ variant
                original_type = item["type"]
                if original_type == "wildcard_host":
                    return {"type": "dns_wildcard_host", "target": item["target"]}
                else:  # host
                    return {"type": "dns_host", "target": item["target"]}
        return None

    def visit_wildcard_host(self, node, visited_children):
        # subdomain_wildcard / label_wildcard
        # The child visitor returns the result directly
        flat = _flatten(visited_children)
        for item in flat:
            if isinstance(item, dict):
                return item
        return None

    def visit_subdomain_wildcard(self, node, visited_children):
        # "*." wildcard_label "." hostname_or_tld
        # Store the full pattern including the "*." prefix
        return {
            "type": "wildcard_host",
            "target": node.text,
        }

    def visit_label_wildcard(self, node, visited_children):
        # wildcard_label "." hostname_or_tld
        # wildcard_label regex already ensures at least one "*" is present
        return {
            "type": "wildcard_host",
            "target": node.text,
        }

    def visit_exact_host(self, node, visited_children):
        # !ipv4_lookahead hostname !(":/")
        _, hostname, _ = visited_children
        return {
            "type": "host",
            "target": _get_text(hostname),
        }

    def visit_ip_rule(self, node, visited_children):
        # ipv4 !("." / "/")
        ipv4, _ = visited_children
        return {
            "type": "ip",
            "target": ipv4 if isinstance(ipv4, str) else _get_text(ipv4),
        }

    def visit_cidr_rule(self, node, visited_children):
        # ipv4 "/" cidr_mask
        ipv4, _, mask = visited_children
        ipv4_text = ipv4 if isinstance(ipv4, str) else _get_text(ipv4)
        mask_text = mask if isinstance(mask, str) else _get_text(mask)
        return {
            "type": "cidr",
            "target": f"{ipv4_text}/{mask_text}",
        }

    def visit_ipv4(self, node, visited_children):
        return node.text

    def visit_cidr_mask(self, node, visited_children):
        return node.text

    def visit_port_attr(self, node, visited_children):
        # ":" port_list
        _, port_list = visited_children
        return {"port": port_list}

    def visit_port_list(self, node, visited_children):
        # port_value ("|" port_value)*
        first, rest = visited_children

        if first == "*":
            return "*"

        ports = [first] if isinstance(first, int) else []
        if isinstance(first, int):
            pass
        elif first == "*":
            return "*"

        flat = _flatten([rest])
        for item in flat:
            if isinstance(item, int):
                ports.append(item)

        return ports if ports else [first] if isinstance(first, int) else first

    def visit_port_value(self, node, visited_children):
        if node.text == "*":
            return "*"
        return int(node.text)

    def visit_proto_attr(self, node, visited_children):
        # "/" protocol
        _, protocol = visited_children
        return {"protocol": protocol}

    def visit_protocol(self, node, visited_children):
        return node.text

    def visit_method_attr(self, node, visited_children):
        # method ("|" method)*
        first, rest = visited_children
        methods = [first]

        flat = _flatten([rest])
        for item in flat:
            if isinstance(item, str) and item in (
                "GET",
                "HEAD",
                "POST",
                "PUT",
                "DELETE",
                "PATCH",
                "OPTIONS",
                "*",
            ):
                methods.append(item)

        return methods

    def visit_method(self, node, visited_children):
        return node.text

    def visit_kv_attrs(self, node, visited_children):
        # (ws+ kv_attr)+
        attrs = []
        flat = _flatten(visited_children)
        for item in flat:
            if isinstance(item, dict):
                attrs.append(item)
        return attrs

    def visit_kv_attr(self, node, visited_children):
        # kv_key "=" kv_value
        key, _, value = visited_children
        key_text = key if isinstance(key, str) else _get_text(key)
        return {key_text: value}

    def visit_kv_key(self, node, visited_children):
        return node.text

    def visit_kv_value(self, node, visited_children):
        flat = _flatten(visited_children)
        for item in flat:
            if isinstance(item, (str, AttrValue)):
                return item
        return visited_children[0] if visited_children else node.text

    def visit_backtick_value(self, node, visited_children):
        # "`" ~"[^`]*" "`"
        # Extract content between backticks
        content = node.text[1:-1]  # Remove surrounding backticks
        return AttrValue(value=content, literal=False)

    def visit_quoted_value(self, node, visited_children):
        # "\"" ~"[^\"]*" "\""
        content = node.text[1:-1]  # Remove surrounding quotes
        return AttrValue(value=content, literal=True)

    def visit_unquoted_value(self, node, visited_children):
        return node.text

    def visit_hostname(self, node, visited_children):
        return node.text

    def visit_hostname_or_tld(self, node, visited_children):
        return node.text

    def visit_scheme(self, node, visited_children):
        return node.text

    def visit_path_rest(self, node, visited_children):
        return node.text

    def generic_visit(self, node, visited_children):
        return visited_children or node


# =============================================================================
# Placeholder substitution
# =============================================================================


def substitute_placeholders(
    policy_text: str,
    owner: str | None = None,
    repo: str | None = None,
) -> str:
    """Substitute {owner} and {repo} placeholders in policy text.

    These placeholders allow policies to reference the current repository
    without hardcoding names. Values come from GITHUB_REPOSITORY env var.

    Args:
        policy_text: The policy text containing placeholders.
        owner: Repository owner (e.g., "anthropics"). If None, placeholder is left as-is.
        repo: Repository name (e.g., "egress-filter"). If None, placeholder is left as-is.

    Returns:
        Policy text with placeholders replaced.

    Example:
        >>> substitute_placeholders(
        ...     "https://github.com/{owner}/{repo}/info/refs",
        ...     owner="anthropics",
        ...     repo="egress-filter"
        ... )
        'https://github.com/anthropics/egress-filter/info/refs'
    """
    result = policy_text
    if owner is not None:
        result = result.replace("{owner}", owner)
    if repo is not None:
        result = result.replace("{repo}", repo)
    return result


def parse_github_repository(github_repository: str | None) -> tuple[str | None, str | None]:
    """Parse GITHUB_REPOSITORY env var into (owner, repo) tuple.

    Args:
        github_repository: Value of GITHUB_REPOSITORY env var (format: "owner/repo").

    Returns:
        Tuple of (owner, repo). Both are None if input is None or invalid.

    Example:
        >>> parse_github_repository("anthropics/egress-filter")
        ('anthropics', 'egress-filter')
        >>> parse_github_repository(None)
        (None, None)
    """
    if not github_repository:
        return None, None

    parts = github_repository.split("/", 1)
    if len(parts) != 2:
        return None, None

    return parts[0], parts[1]


# =============================================================================
# Public API
# =============================================================================


def parse_policy(
    policy_text: str,
    defaults: DefaultContext | None = None,
) -> list[Rule]:
    """Parse a policy text into a list of flattened rules.

    Uses PEG grammar for parsing - invalid syntax is rejected at parse time.
    Headers set context for subsequent rules. Each rule is self-sufficient
    after parsing (context is inlined into the rule).

    Invalid lines are silently skipped (lenient parsing per design doc).

    Args:
        policy_text: The policy text to parse.
        defaults: Optional DefaultContext to override the security-conscious
            defaults (port=443, protocol=tcp, methods=[GET,HEAD], attrs={}).
            Use this to inject runtime constraints like cgroup matching.
    """
    # Single visitor instance reused across all lines (preserves header context)
    visitor = PolicyVisitor(defaults=defaults)
    all_rules: list[Rule] = []

    for line in policy_text.splitlines():
        try:
            tree = GRAMMAR.parse(line)
            # Reset rules/warnings for this line (context is preserved across lines)
            visitor.rules = []
            visitor.warnings = []
            visitor.visit(tree)
            # Collect rules from this line
            all_rules.extend(visitor.rules)
        except ParseError:
            # Invalid line - skip (lenient parsing)
            pass

    return all_rules


def flatten_policy(policy_text: str):
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

    result = {
        "type": rule.type,
        "target": rule.target,
        "port": rule.port,
        "protocol": rule.protocol,
        "methods": rule.methods,
        "url_base": rule.url_base,
        "attrs": attrs_dict,
    }
    if rule.passthrough:
        result["passthrough"] = True
    return result


def validate_policy(policy_text: str) -> list[tuple[int, str, str]]:
    """Validate a policy and return list of errors for invalid lines.

    Args:
        policy_text: The policy text to validate.

    Returns:
        List of (line_num, line_text, error_message) tuples for invalid lines.
        Empty list if all lines are valid.
    """
    errors = []
    visitor = PolicyVisitor()
    all_rules: list[Rule] = []

    for line_num, line in enumerate(policy_text.splitlines(), start=1):
        line_stripped = line.strip()

        try:
            tree = GRAMMAR.parse(line)
            visitor.rules = []
            visitor.warnings = []
            visitor.visit(tree)
            all_rules.extend(visitor.rules)
            for warning in visitor.warnings:
                errors.append((line_num, line_stripped, warning))
        except ParseError as e:
            errors.append((line_num, line_stripped, str(e)))

    # Cross-rule validation: warn if passthrough overlaps with URL/path rules
    errors.extend(_check_passthrough_url_overlap(all_rules))

    return errors


def _extract_url_rule_hostname(rule: Rule) -> str | None:
    """Extract the hostname from a URL or path rule's target."""
    if rule.type == "url":
        return urlparse(rule.target).hostname
    elif rule.type == "path" and rule.url_base:
        return urlparse(rule.url_base).hostname
    return None


def _check_passthrough_url_overlap(
    rules: list[Rule],
) -> list[tuple[int, str, str]]:
    """Warn when passthrough rules overlap with URL/path allow rules.

    Passthrough skips MITM, so URL path/method filtering won't apply.
    """
    from .matcher import match_hostname

    passthrough_rules = [r for r in rules if r.passthrough]
    url_path_rules = [r for r in rules if r.type in ("url", "path") and not r.passthrough]

    if not passthrough_rules or not url_path_rules:
        return []

    warnings = []
    for pt_rule in passthrough_rules:
        is_wildcard = pt_rule.type == "wildcard_host"
        for url_rule in url_path_rules:
            url_hostname = _extract_url_rule_hostname(url_rule)
            if url_hostname and match_hostname(
                pt_rule.target, url_hostname, is_wildcard=is_wildcard
            ):
                warnings.append((
                    0,
                    f"{pt_rule.target} passthrough",
                    f"passthrough rule '{pt_rule.target}' overlaps with URL/path rule "
                    f"'{url_rule.target}' — URL path and method filtering will not apply "
                    f"because passthrough skips TLS interception",
                ))
    return warnings
