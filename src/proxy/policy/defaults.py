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

# TODO: Determine minimal required rules from baseline testing
"""

# Optional presets that users can include
DOCKER_PRESET = """
# =============================================================================
# Docker Registry Access
# =============================================================================
# Allows the Docker daemon to pull images from Docker Hub.

[exe=/usr/bin/dockerd]
registry-1.docker.io
auth.docker.io
*.docker.io
production.cloudflare.docker.com
"""

# Registry of available presets
PRESETS = {
    "defaults": GITHUB_ACTIONS_DEFAULTS,
    "docker": DOCKER_PRESET,
}


def get_preset(name: str) -> str | None:
    """Get a preset policy by name."""
    return PRESETS.get(name)


def get_defaults() -> str:
    """Get the default GitHub Actions infrastructure rules."""
    return GITHUB_ACTIONS_DEFAULTS
