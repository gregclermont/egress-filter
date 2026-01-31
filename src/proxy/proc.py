"""Process information utilities for reading /proc filesystem."""

import os
from pathlib import Path

from proxy.policy.gha import RUNNER_CGROUP, RUNNER_WORKER_EXE


# =============================================================================
# Low-level /proc readers
# =============================================================================

def read_exe(pid: int) -> str:
    """Read executable path from /proc/[pid]/exe symlink."""
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except (OSError, FileNotFoundError):
        return ""


def read_cmdline(pid: int) -> str:
    """Read command line from /proc/[pid]/cmdline as space-separated string."""
    try:
        data = Path(f"/proc/{pid}/cmdline").read_bytes()
        return data.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except (OSError, FileNotFoundError):
        return ""


def read_cmdline_list(pid: int) -> list[str]:
    """Read command line from /proc/[pid]/cmdline as list of arguments."""
    try:
        data = Path(f"/proc/{pid}/cmdline").read_bytes()
        if data:
            return [arg.decode("utf-8", errors="replace") for arg in data.rstrip(b"\x00").split(b"\x00")]
        return []
    except (OSError, FileNotFoundError):
        return []


def read_environ(pid: int) -> dict[str, str]:
    """Read environment variables from /proc/[pid]/environ."""
    try:
        data = Path(f"/proc/{pid}/environ").read_bytes()
        env = {}
        for item in data.split(b"\x00"):
            if b"=" in item:
                key, value = item.split(b"=", 1)
                env[key.decode("utf-8", errors="replace")] = value.decode("utf-8", errors="replace")
        return env
    except (OSError, FileNotFoundError):
        return {}


def read_cgroup(pid: int) -> str:
    """Read full cgroup line from /proc/[pid]/cgroup."""
    try:
        return Path(f"/proc/{pid}/cgroup").read_text().strip()
    except (OSError, FileNotFoundError):
        return ""


def read_ppid(pid: int) -> int | None:
    """Read parent PID from /proc/[pid]/stat."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        # Format: pid (comm) state ppid ...
        # comm can contain spaces and parens, so parse carefully
        end = stat.rindex(")")
        rest = stat[end + 2:].split()
        return int(rest[1])  # ppid is after state
    except (OSError, FileNotFoundError, ValueError, IndexError):
        return None


# =============================================================================
# Higher-level utilities
# =============================================================================

def get_cgroup_path(pid: int) -> str | None:
    """Get the cgroup path portion for a process.

    Returns just the path from /proc/pid/cgroup, or None if unavailable.
    For cgroup v2, returns the unified path. For v1, returns the first path.
    """
    content = read_cgroup(pid)
    if not content:
        return None
    # cgroup v2: single line like "0::/user.slice/..."
    # cgroup v1: multiple lines like "12:memory:/docker/..."
    for line in content.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3:
            return parts[2]  # Return the path portion
    return None


def is_container_process(pid: int) -> bool:
    """Check if a process is running inside a Docker container."""
    cgroup = get_cgroup_path(pid)
    if not cgroup:
        return False
    return "docker-" in cgroup or "/docker/" in cgroup


def get_process_ancestry(pid: int, max_depth: int = 10) -> list[tuple[int, str]]:
    """Get process ancestry as list of (pid, exe) tuples.

    Uses full executable path instead of comm to reduce spoofing risk.
    """
    ancestry = []
    current_pid = pid

    for _ in range(max_depth):
        exe = read_exe(current_pid)
        if not exe:
            break

        ancestry.append((current_pid, exe))

        ppid = read_ppid(current_pid)
        if not ppid or ppid <= 1:  # Reached init or error
            break
        current_pid = ppid

    return ancestry


def is_runner_process(pid: int) -> bool:
    """Check if process is in the runner cgroup (quick filter)."""
    cgroup = get_cgroup_path(pid)
    return cgroup == RUNNER_CGROUP if cgroup else False


def find_trusted_github_pids(pid: int) -> list[int]:
    """Find PIDs we trust for GitHub env vars (direct child of Runner.Worker).

    Runner.Worker itself does NOT have GITHUB_* env vars - it sets them
    in the child process environment when spawning steps.

    Returns empty list if:
    - Process is not in runner cgroup (Docker, Azure agent, etc.)
    - Runner.Worker not found in ancestry
    - Process is Runner.Worker itself (no direct child)
    """
    # Quick cgroup check first
    if not is_runner_process(pid):
        return []

    ancestry = get_process_ancestry(pid)

    # Find Runner.Worker in ancestry (using full exe path to prevent spoofing)
    runner_idx = None
    for i, (p, exe) in enumerate(ancestry):
        if exe == RUNNER_WORKER_EXE:
            runner_idx = i
            break

    if runner_idx is None:
        return []  # Not under runner worker

    # Trust only the direct child of Runner.Worker (the step process)
    # Runner.Worker itself has no GITHUB_* env vars
    if runner_idx > 0:
        direct_child = ancestry[runner_idx - 1]
        return [direct_child[0]]  # Direct child only

    return []  # Process is Runner.Worker itself, no env vars to trust


def get_trusted_github_env(pid: int) -> dict[str, str]:
    """Get environment variables from trusted ancestry.

    Only trusts env vars from Runner.Worker's direct child,
    preventing spoofing by malicious descendant processes.

    Returns empty dict if no trusted process found.
    """
    for trusted_pid in find_trusted_github_pids(pid):
        return read_environ(trusted_pid)
    return {}


def get_proc_info(pid: int | None) -> dict:
    """Get process info from /proc: exe, cmdline, cgroup, GitHub Actions step/action."""
    if not pid:
        return {}
    result = {}
    exe = read_exe(pid)
    if exe:
        result["exe"] = exe
    cmdline = read_cmdline_list(pid)
    if cmdline:
        result["cmdline"] = cmdline
    cgroup = get_cgroup_path(pid)
    if cgroup:
        result["cgroup"] = cgroup

    # Get GitHub env vars from trusted ancestry (single read)
    trusted_env = get_trusted_github_env(pid)
    job = trusted_env.get("GITHUB_JOB", "")
    action_id = trusted_env.get("GITHUB_ACTION", "")
    if job and action_id:
        result["step"] = f"{job}.{action_id}"
    action_repo = trusted_env.get("GITHUB_ACTION_REPOSITORY", "")
    if action_repo:
        result["action"] = action_repo

    return result
