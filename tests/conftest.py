"""Shared test fixtures and mocks."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.policy.enforcer import Decision, Verdict


class MockBPFState:
    """Minimal BPFState mock with configurable PID lookup."""

    def __init__(self, pid=1234):
        self._pid = pid
        self.dns_cache = {}

    def lookup_pid(self, dst_ip, src_port, dst_port, protocol=6):
        return self._pid


def make_decision(allowed, rule_idx=0):
    """Create a real Decision object."""
    if allowed:
        return Decision(
            verdict=Verdict.ALLOW,
            reason=f"Matched rule {rule_idx}",
            matched_rule=rule_idx,
        )
    return Decision(
        verdict=Verdict.BLOCK,
        reason="No matching rule",
        matched_rule=None,
    )
