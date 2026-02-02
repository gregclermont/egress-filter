"""GitHub Actions hosted runner environment constants.

These are facts about the GitHub-hosted runner environment, independent
of any specific action. They're used for:
- Scoping policy rules to the runner process tree (cgroup)
- Identifying trusted process ancestry (Runner.Worker exe path)
"""

import os
from pathlib import Path

# Cgroup path for processes in the runner's process tree
# Used to distinguish runner processes from Docker containers, Azure agent, etc.
RUNNER_CGROUP = "/system.slice/hosted-compute-agent.service"

# Full path to the Runner.Worker executable
# This process spawns each step and sets GITHUB_* env vars in children
RUNNER_WORKER_EXE = "/home/runner/actions-runner/cached/bin/Runner.Worker"

# Node.js executable path for actions using node24 runtime
# Must match the 'using' field in action.yml
NODE24_EXE = "/home/runner/actions-runner/cached/externals/node24/bin/node"


def validate_runner_environment() -> list[str]:
    """Validate that expected runner paths exist.

    Returns list of error messages (empty if all valid).
    """
    errors = []

    # Check Runner.Worker executable
    if not os.path.isfile(RUNNER_WORKER_EXE):
        errors.append(f"Runner.Worker not found at {RUNNER_WORKER_EXE}")

    # Check Node.js executable
    if not os.path.isfile(NODE24_EXE):
        errors.append(f"Node.js (node24) not found at {NODE24_EXE}")

    # Check cgroup
    try:
        cgroup_content = Path("/proc/self/cgroup").read_text()
        # cgroup v2 format: "0::/path" - extract the path
        for line in cgroup_content.strip().splitlines():
            parts = line.split(":", 2)
            if len(parts) == 3:
                cgroup_path = parts[2]
                if cgroup_path != RUNNER_CGROUP:
                    errors.append(
                        f"Unexpected cgroup: got {cgroup_path}, expected {RUNNER_CGROUP}"
                    )
                break
    except (OSError, FileNotFoundError) as e:
        errors.append(f"Could not read cgroup: {e}")

    return errors
