"""Policy parsing and matching engine."""

from .defaults import RUNNER_DEFAULTS
from .gha import NODE24_EXE, RUNNER_CGROUP, RUNNER_WORKER_EXE
from .dns_cache import DNSIPCache
from .enforcer import Decision, PolicyEnforcer, ProcessInfo, Verdict
from .matcher import ConnectionEvent, PolicyMatcher, match_rule
from .parser import (
    flatten_policy,
    parse_github_repository,
    parse_policy,
    rule_to_dict,
    substitute_placeholders,
    validate_policy,
)
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
    "NODE24_EXE",
    "RUNNER_CGROUP",
    "RUNNER_WORKER_EXE",
    "RUNNER_DEFAULTS",
    # Parser
    "parse_policy",
    "flatten_policy",
    "rule_to_dict",
    "substitute_placeholders",
    "parse_github_repository",
    "validate_policy",
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
