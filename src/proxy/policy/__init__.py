"""Policy parsing and matching engine."""

from .defaults import RUNNER_CGROUP, RUNNER_DEFAULTS
from .dns_cache import DNSIPCache
from .enforcer import Decision, PolicyEnforcer, ProcessInfo, Verdict
from .matcher import ConnectionEvent, PolicyMatcher, match_rule
from .parser import flatten_policy, parse_policy, rule_to_dict
from .types import (
    SECURE_DEFAULTS,
    AttrValue,
    DefaultContext,
    HeaderContext,
    Rule,
)

__all__ = [
    # Types
    "Rule",
    "AttrValue",
    "HeaderContext",
    "DefaultContext",
    "SECURE_DEFAULTS",
    "RUNNER_CGROUP",
    "RUNNER_DEFAULTS",
    # Parser
    "parse_policy",
    "flatten_policy",
    "rule_to_dict",
    # Matcher
    "ConnectionEvent",
    "PolicyMatcher",
    "match_rule",
    # DNS Cache
    "DNSIPCache",
    # Enforcer
    "PolicyEnforcer",
    "Decision",
    "Verdict",
    "ProcessInfo",
]
