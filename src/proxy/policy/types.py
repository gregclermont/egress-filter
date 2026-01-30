"""Policy rule types and data structures."""

from dataclasses import dataclass, field
from typing import Literal

RuleType = Literal["host", "wildcard_host", "ip", "cidr", "url", "path"]
Protocol = Literal["tcp", "udp"]


@dataclass
class AttrValue:
    """Attribute value that may be literal (no wildcards) or pattern (wildcards active)."""

    value: str
    literal: bool = False  # True = no wildcards, False = wildcards active


@dataclass
class Rule:
    """A flattened, self-sufficient policy rule."""

    type: RuleType
    target: str  # hostname, IP, CIDR, URL, or path
    port: list[int] | Literal["*"]  # List of ports or "*" for any
    protocol: Protocol
    methods: list[str] | None  # HTTP methods for URL/path rules, None for others
    url_base: str | None  # Base URL for path rules, None for others
    attrs: dict[str, str | AttrValue] = field(default_factory=dict)


@dataclass
class DefaultContext:
    """Default values for header context.

    These security-conscious defaults are applied when:
    - Parsing begins (initial context)
    - A [] header resets the context

    All defaults bias toward security:
    - port: 443 (HTTPS, not 80 or *)
    - protocol: tcp (not UDP or *)
    - methods: ["GET", "HEAD"] for URL/path rules (read-only, not *)
    - attrs: {} (no constraints, but caller can add cgroup etc.)
    """

    port: list[int] | Literal["*"] = field(default_factory=lambda: [443])
    protocol: Protocol = "tcp"
    methods: list[str] = field(default_factory=lambda: ["GET", "HEAD"])
    attrs: dict[str, str | AttrValue] = field(default_factory=dict)


# The built-in security-conscious defaults
SECURE_DEFAULTS = DefaultContext()


@dataclass
class HeaderContext:
    """Current header context for rule parsing.

    Tracks the current header settings that apply to subsequent rules.
    Can be reset to defaults via [] header.
    """

    port: list[int] | Literal["*"] = field(default_factory=lambda: [443])
    protocol: Protocol = "tcp"
    methods: list[str] | None = None  # None means use defaults from DefaultContext
    url_base: str | None = None
    attrs: dict[str, str | AttrValue] = field(default_factory=dict)
    _defaults: DefaultContext = field(default_factory=lambda: SECURE_DEFAULTS)

    def reset(self) -> None:
        """Reset to default values."""
        self.port = (
            list(self._defaults.port)
            if isinstance(self._defaults.port, list)
            else self._defaults.port
        )
        self.protocol = self._defaults.protocol
        self.methods = None  # Will use _defaults.methods when needed
        self.url_base = None
        self.attrs = dict(self._defaults.attrs)
