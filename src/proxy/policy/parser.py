"""Policy parser - converts policy text to flattened rules using PEG grammar.

Uses parsimonious for PEG parsing. The grammar is the source of truth for
what syntax is valid - validation happens at parse time, not after.
"""

import logging

from parsimonious.exceptions import ParseError
from parsimonious.grammar import Grammar
from parsimonious.nodes import Node, NodeVisitor

from .types import AttrValue, HeaderContext, Protocol, Rule

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

header          = ws* "[" header_attrs? "]" inline_comment? ws*
header_attrs    = url_base / method_attr / port_proto_attr
url_base        = scheme "://" hostname url_port? url_path?
port_proto_attr = port_attr proto_attr?

rule            = ws* (url_rule / path_rule / cidr_rule / ip_rule / host_rule) port_proto_attr? kv_attrs? inline_comment? ws*

url_rule        = (method_attr ws+)? scheme "://" hostname url_port? url_path
scheme          = "https" / "http"
url_port        = ":" port_value
url_path        = "/" path_rest
path_rest       = ~"[a-zA-Z0-9_.~*/%+-]*"

path_rule       = (method_attr ws+)? "/" path_rest

host_rule       = wildcard_host / exact_host
wildcard_host   = "*." hostname_or_tld
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
kv_key          = arg_indexed / ~"[a-z]+"
arg_indexed     = "arg[" ~"[0-9]+" "]"
kv_value        = backtick_value / quoted_value / unquoted_value
backtick_value  = "`" ~"[^`]*" "`"
quoted_value    = "\"" ~"[^\"]*" "\""
unquoted_value  = ~"[^\\s#]+"
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
    return ""


def _is_empty(visited):
    """Check if visited children represent an empty/optional match."""
    if visited is None:
        return True
    if isinstance(visited, Node):
        return visited.text == ""
    if isinstance(visited, list):
        return len(visited) == 0 or all(_is_empty(x) for x in visited)
    if isinstance(visited, str):
        return visited == ""
    return False


def _flatten(lst):
    """Flatten nested lists, filtering out empty nodes."""
    result = []
    for item in lst:
        if isinstance(item, list):
            result.extend(_flatten(item))
        elif item is not None and not _is_empty(item):
            result.append(item)
    return result


# =============================================================================
# AST Visitor - transforms parse tree to Rule objects
# =============================================================================


class PolicyVisitor(NodeVisitor):
    """Visits parse tree and extracts structured data."""

    def __init__(self):
        self.rules = []
        self.ctx = HeaderContext()

    def visit_policy(self, node, visited_children):
        return self.rules

    def visit_line(self, node, visited_children):
        return visited_children[0] if visited_children else None

    def visit_header(self, node, visited_children):
        # ws* "[" header_attrs? "]" inline_comment? ws*
        _, _, header_attrs, _, _, _ = visited_children

        # Reset context for new header
        self.ctx.reset()

        if not _is_empty(header_attrs):
            attrs = _flatten(header_attrs)

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
                            if attr["url_base"].startswith("https://"):
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
        return None

    def visit_header_attrs(self, node, visited_children):
        return visited_children[0]

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
        # ws* (url_rule / path_rule / cidr_rule / ip_rule / host_rule) port_proto_attr? kv_attrs? inline_comment? ws*
        _, rule_data, port_proto, kv_attrs, _, _ = visited_children

        # Extract rule info from nested structure
        rule_info = None
        flat_rule = _flatten([rule_data])
        for item in flat_rule:
            if isinstance(item, dict) and "type" in item:
                rule_info = item
                break

        if not rule_info:
            return None

        # Apply port/proto from rule or context
        port = self.ctx.port
        protocol = self.ctx.protocol

        # For URL rules, derive port from scheme if not in context
        rule_type = rule_info.get("type")
        target = rule_info.get("target")
        if rule_type == "url" and target:
            if target.startswith("http://"):
                port = [80]
            elif target.startswith("https://"):
                port = [443]

        if not _is_empty(port_proto):
            flat_pp = _flatten([port_proto])
            for item in flat_pp:
                if isinstance(item, dict):
                    if "port" in item:
                        port = item["port"]
                    if "protocol" in item:
                        protocol = item["protocol"]

        # Extract attributes
        attrs = {}
        if not _is_empty(kv_attrs):
            flat_attrs = _flatten([kv_attrs])
            for attr in flat_attrs:
                if isinstance(attr, dict) and "type" not in attr:
                    attrs.update(attr)

        # Build the Rule (rule_type and target already extracted above)
        methods = rule_info.get("methods")
        url_base = rule_info.get("url_base")

        # Apply context defaults for methods on URL/path rules
        if rule_type in ("url", "path") and methods is None:
            methods = self.ctx.methods if self.ctx.methods else ["GET", "HEAD"]

        # Path rules need URL base from context
        if rule_type == "path":
            url_base = self.ctx.url_base
            if url_base is None:
                # Path rule without URL context - skip
                return None

        rule = Rule(
            type=rule_type,
            target=target,
            port=port,
            protocol=protocol,
            methods=methods,
            url_base=url_base,
            attrs=attrs,
        )
        self.rules.append(rule)
        return rule

    def visit_url_rule(self, node, visited_children):
        # (method_attr ws+)? scheme "://" hostname url_port? url_path
        method_part, scheme, _, hostname, url_port, url_path = visited_children

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
        hostname_text = _get_text(hostname)
        port_text = _get_text(url_port)
        path_text = _get_text(url_path)

        target = f"{scheme_text}://{hostname_text}{port_text}{path_text}"

        return {
            "type": "url",
            "target": target,
            "methods": methods,
        }

    def visit_path_rule(self, node, visited_children):
        # (method_attr ws+)? "/" path_rest
        method_part, slash, path_rest = visited_children

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

        return {
            "type": "path",
            "target": target,
            "methods": methods,
            "url_base": None,
        }

    def visit_host_rule(self, node, visited_children):
        flat = _flatten(visited_children)
        for item in flat:
            if isinstance(item, dict):
                return item
        return None

    def visit_wildcard_host(self, node, visited_children):
        # "*." hostname_or_tld
        _, hostname = visited_children
        return {
            "type": "wildcard_host",
            "target": _get_text(hostname),
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
# Public API
# =============================================================================


def parse_policy(policy_text: str) -> list[Rule]:
    """Parse a policy text into a list of flattened rules.

    Uses PEG grammar for parsing - invalid syntax is rejected at parse time.
    Headers set context for subsequent rules. Each rule is self-sufficient
    after parsing (context is inlined into the rule).

    Invalid lines are silently skipped (lenient parsing per design doc).
    Skipped lines are logged at DEBUG level.
    """
    # Single visitor instance reused across all lines (preserves header context)
    visitor = PolicyVisitor()
    all_rules: list[Rule] = []

    for line_num, line in enumerate(policy_text.splitlines(), start=1):
        line_stripped = line.strip()

        # Skip empty lines and comments
        if not line_stripped or line_stripped.startswith("#"):
            continue

        try:
            tree = GRAMMAR.parse(line)
            # Reset rules list for this line (context is preserved across lines)
            visitor.rules = []
            visitor.visit(tree)
            # Collect rules from this line
            all_rules.extend(visitor.rules)
        except ParseError as e:
            # Invalid line - skip (lenient parsing) but log for debugging
            logger.debug(
                "Skipping invalid policy line %d: %r (%s)", line_num, line_stripped, e
            )

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

    return {
        "type": rule.type,
        "target": rule.target,
        "port": rule.port,
        "protocol": rule.protocol,
        "methods": rule.methods,
        "url_base": rule.url_base,
        "attrs": attrs_dict,
    }
