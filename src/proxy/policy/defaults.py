"""Default policy rules for GitHub Actions infrastructure.

These rules allow essential connections that are required for GitHub Actions
to function properly. They can be auto-included with `include: defaults` or
via the enforcer's `include_defaults=True` option.
"""

from .gha import RUNNER_CGROUP
from .types import DefaultContext

# Defaults for GitHub Actions runner (includes cgroup constraint)
# This ensures all rules only match connections from the runner process tree
RUNNER_DEFAULTS = DefaultContext(attrs={"cgroup": RUNNER_CGROUP})

# Default rules for GitHub-hosted runners
# These are automatically applied unless disabled
DEFAULT_POLICY = """
# =============================================================================
# GitHub Actions Infrastructure Defaults
# =============================================================================
# These rules allow essential connections required for GitHub Actions.
# They are restrictive by design - each rule is scoped to specific executables
# or cgroups where possible to prevent abuse.

# Local DNS resolver (systemd-resolved)
# Allows DNS queries to the local resolver. Domain checks still apply -
# only domains allowed by other rules can be resolved.
127.0.0.53:53/udp

# Azure wireserver (metadata/heartbeat for GitHub-hosted runners)
# The WALinuxAgent runs in the background and must access the wireserver.
168.63.129.16:80|32526 cgroup=/azure.slice/walinuxagent.service

# GitHub Actions results receiver (job status reporting)
# Various runner processes (Runner.Worker, action node processes) need this.
results-receiver.actions.githubusercontent.com

# Hosted compute watchdog (provisioning agent telemetry)
# The provjobd daemon sends traces to a datacenter-specific endpoint.
[exe=/tmp/provjobd*]
hosted-compute-watchdog-prod-*.githubapp.com

# Reset context for user rules that follow
[]
"""

# Registry of available presets
PRESETS = {
    "defaults": DEFAULT_POLICY,
}


def get_preset(name: str) -> str | None:
    """Get a preset policy by name."""
    return PRESETS.get(name)


def get_defaults() -> str:
    """Get the default GitHub Actions infrastructure rules."""
    return DEFAULT_POLICY
