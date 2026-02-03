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


def get_process_ancestry() -> list[tuple[int, str]]:
    """Walk up the process tree and return [(pid, exe_path), ...].

    Starts with current process and walks up to init (PID 1).
    """
    ancestry = []
    pid = os.getpid()

    while pid > 0:
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
            ancestry.append((pid, exe))

            # Get parent PID from /proc/PID/stat
            stat = Path(f"/proc/{pid}/stat").read_text()
            # Format: "pid (comm) state ppid ..." - ppid is 4th field
            # Handle comm containing spaces/parens by finding last ')'
            ppid_start = stat.rfind(")") + 2
            ppid = int(stat[ppid_start:].split()[1])

            if ppid == pid:  # Reached init
                break
            pid = ppid
        except (OSError, FileNotFoundError, ValueError):
            break

    return ancestry


def validate_runner_environment() -> list[str]:
    """Validate that we're running under the expected GitHub runner process tree.

    Checks process ancestry for Runner.Worker and node24, plus cgroup.
    Returns list of error messages (empty if all valid).
    """
    errors = []
    ancestry = get_process_ancestry()
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
