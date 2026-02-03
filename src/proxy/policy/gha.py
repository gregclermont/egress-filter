"""GitHub Actions hosted runner environment constants.

These are facts about the GitHub-hosted runner environment, independent
of any specific action. They're used for:
- Scoping policy rules to the runner process tree (cgroup)
- Identifying trusted process ancestry (Runner.Worker exe path)
"""

import os

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
    """Validate that we're running under the expected GitHub runner process tree.

    Checks process ancestry for Runner.Worker and node24, plus cgroup.
    Returns list of error messages (empty if all valid).
    """
    # Lazy import to avoid circular dependency (proc.py imports from gha.py)
    from proxy.proc import get_cgroup_path, get_process_ancestry

    errors = []
    ancestry = get_process_ancestry(os.getpid())
    exe_paths = [exe for _, exe in ancestry]

    # Check for Runner.Worker in ancestry
    if RUNNER_WORKER_EXE not in exe_paths:
        errors.append(
            f"Runner.Worker ({RUNNER_WORKER_EXE}) not found in process ancestry"
        )

    # Check for node24 in ancestry
    if NODE24_EXE not in exe_paths:
        errors.append(f"Node.js ({NODE24_EXE}) not found in process ancestry")

    # Check cgroup
    cgroup_path = get_cgroup_path(os.getpid())
    if cgroup_path is None:
        errors.append("Could not read cgroup")
    elif cgroup_path != RUNNER_CGROUP:
        errors.append(f"Unexpected cgroup: got {cgroup_path}, expected {RUNNER_CGROUP}")

    return errors
