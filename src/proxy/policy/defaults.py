"""Default policy rules for GitHub Actions infrastructure.

These rules allow essential connections that are required for GitHub Actions
to function properly. They can be auto-included with `include: defaults` or
via the enforcer's `include_defaults=True` option.
"""

from .types import DefaultContext

# GitHub Actions runner cgroup - used to scope rules to the runner process tree
RUNNER_CGROUP = "/system.slice/hosted-compute-agent.service"

# Defaults for GitHub Actions runner (includes cgroup constraint)
# This ensures all rules only match connections from the runner process tree
RUNNER_DEFAULTS = DefaultContext(attrs={"cgroup": RUNNER_CGROUP})

# Default rules for GitHub-hosted runners
# These are automatically applied unless disabled
GITHUB_ACTIONS_DEFAULTS = """
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
# The runner worker process reports job results to GitHub.
[exe=/home/runner/actions-runner/cached/bin/Runner.Worker]
results-receiver.actions.githubusercontent.com
"""

# Registry of available presets
PRESETS = {
    "defaults": GITHUB_ACTIONS_DEFAULTS,
}


def get_preset(name: str) -> str | None:
    """Get a preset policy by name."""
    return PRESETS.get(name)


def get_defaults() -> str:
    """Get the default GitHub Actions infrastructure rules."""
    return GITHUB_ACTIONS_DEFAULTS
