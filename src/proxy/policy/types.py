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
class HeaderContext:
    """Current header context for rule parsing."""

    port: list[int] | Literal["*"] = field(default_factory=lambda: [443])
    protocol: Protocol = "tcp"
    methods: list[str] | None = None  # None means use defaults per rule type
    url_base: str | None = None
    attrs: dict[str, str | AttrValue] = field(default_factory=dict)

    def reset(self) -> None:
        """Reset to default values."""
        self.port = [443]
        self.protocol = "tcp"
        self.methods = None
        self.url_base = None
        self.attrs = {}
