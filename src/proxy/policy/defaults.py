"""Default policy rules for GitHub Actions infrastructure.

These rules allow essential connections that are required for GitHub Actions
to function properly. They can be auto-included with `include: defaults` or
via the enforcer's `include_defaults=True` option.
"""

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

# Reset to defaults for user rules that follow
[]
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
