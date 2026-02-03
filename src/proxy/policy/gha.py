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

    Checks process ancestry for Runner.Worker and node24 at expected positions.
    Returns list of error messages (empty if all valid).

    Expected ancestry (from self outward):
      [0] python3      <- proxy
      [1] bash
      [2] bash
      [3] sudo
      [4] node24       <- action runtime
      [5] Runner.Worker <- step spawner
      [6] Runner.Listener
      [7] hosted-compute-agent
    """
    # Lazy import to avoid circular dependency (proc.py imports from gha.py)
    from proxy.proc import get_process_ancestry

    errors = []
    ancestry = get_process_ancestry(os.getpid(), max_depth=10)
    exe_paths = [exe for _, exe in ancestry]

    # Expected positions (with tolerance for minor variations)
    # node24 should be around index 4, Runner.Worker around index 5
    node24_idx = exe_paths.index(NODE24_EXE) if NODE24_EXE in exe_paths else -1
    worker_idx = exe_paths.index(RUNNER_WORKER_EXE) if RUNNER_WORKER_EXE in exe_paths else -1

    if node24_idx == -1:
        errors.append(f"node24 ({NODE24_EXE}) not found in process ancestry")
    elif node24_idx not in (3, 4, 5):
        errors.append(f"node24 at unexpected position {node24_idx}, expected 3-5")

    if worker_idx == -1:
        errors.append(f"Runner.Worker ({RUNNER_WORKER_EXE}) not found in process ancestry")
    elif worker_idx not in (4, 5, 6):
        errors.append(f"Runner.Worker at unexpected position {worker_idx}, expected 4-6")

    # Runner.Worker must be an ancestor of node24 (higher index = further up tree)
    if node24_idx >= 0 and worker_idx >= 0 and worker_idx <= node24_idx:
        errors.append(
            f"Runner.Worker (idx {worker_idx}) should be ancestor of node24 (idx {node24_idx})"
        )

    return errors
