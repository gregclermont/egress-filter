"""Process information utilities for reading /proc filesystem."""

import os
from pathlib import Path


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


# Backward compatibility alias
get_cgroup = get_cgroup_path


def is_container_process(pid: int) -> bool:
    """Check if a process is running inside a Docker container."""
    cgroup = get_cgroup_path(pid)
    if not cgroup:
        return False
    return "docker-" in cgroup or "/docker/" in cgroup


def read_comm(pid: int) -> str:
    """Read process name (comm) from /proc/[pid]/stat."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        # Format: pid (comm) state ppid ...
        # comm can contain spaces and parens, so parse carefully
        start = stat.index("(") + 1
        end = stat.rindex(")")
        return stat[start:end]
    except (OSError, FileNotFoundError, ValueError, IndexError):
        return ""


def get_process_ancestry(pid: int, max_depth: int = 10) -> list[tuple[int, str]]:
    """Get process ancestry as list of (pid, comm) tuples."""
    ancestry = []
    current_pid = pid

    for _ in range(max_depth):
        comm = read_comm(current_pid)
        if not comm:
            break

        ancestry.append((current_pid, comm))

        ppid = read_ppid(current_pid)
        if not ppid or ppid <= 1:  # Reached init or error
            break
        current_pid = ppid

    return ancestry


def get_github_step(pid: int) -> str | None:
    """Get GitHub Actions step identifier by walking up the process tree."""
    visited = set()
    while pid and pid > 1 and pid not in visited:
        visited.add(pid)
        try:
            env = read_environ(pid)
            job = env.get("GITHUB_JOB", "")
            action = env.get("GITHUB_ACTION", "")
            if job and action:
                return f"{job}.{action}"
            # Walk up to parent
            ppid = read_ppid(pid)
            if not ppid:
                break
            pid = ppid
        except Exception:
            break
    return None


def get_github_action_repo(pid: int) -> str | None:
    """Get GitHub Actions action repository by walking up the process tree.

    Returns the value of GITHUB_ACTION_REPOSITORY (e.g., "actions/checkout")
    which identifies the action being run, regardless of custom step ids.
    """
    visited = set()
    while pid and pid > 1 and pid not in visited:
        visited.add(pid)
        try:
            env = read_environ(pid)
            action_repo = env.get("GITHUB_ACTION_REPOSITORY", "")
            if action_repo:
                return action_repo
            # Walk up to parent
            ppid = read_ppid(pid)
            if not ppid:
                break
            pid = ppid
        except Exception:
            break
    return None


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
    step = get_github_step(pid)
    if step:
        result["step"] = step
    action = get_github_action_repo(pid)
    if action:
        result["action"] = action
    return result
