"""Process information utilities."""

import os
from pathlib import Path


def get_github_step(pid: int) -> str | None:
    """Get GitHub Actions step identifier by walking up the process tree."""
    visited = set()
    while pid and pid > 1 and pid not in visited:
        visited.add(pid)
        try:
            environ = Path(f"/proc/{pid}/environ").read_bytes()
            # Fast check before parsing
            if b"GITHUB_JOB" not in environ:
                pass  # Fall through to get parent
            else:
                env_vars = dict(
                    kv.split(b"=", 1) for kv in environ.split(b"\x00")
                    if b"=" in kv
                )
                job = env_vars.get(b"GITHUB_JOB", b"").decode("utf-8", errors="replace")
                action = env_vars.get(b"GITHUB_ACTION", b"").decode("utf-8", errors="replace")
                if job and action:
                    return f"{job}.{action}"
            # Get parent PID from /proc/{pid}/status
            status = Path(f"/proc/{pid}/status").read_text()
            for line in status.splitlines():
                if line.startswith("PPid:"):
                    pid = int(line.split()[1])
                    break
            else:
                break
        except (OSError, FileNotFoundError, ValueError):
            break
    return None


def get_proc_info(pid: int | None) -> dict:
    """Get process info from /proc: exe, cmdline, GitHub Actions step."""
    if not pid:
        return {}
    result = {}
    try:
        result["exe"] = os.readlink(f"/proc/{pid}/exe")
    except (OSError, FileNotFoundError):
        pass
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        if cmdline:
            # Null-separated args -> list
            result["cmdline"] = [arg.decode("utf-8", errors="replace") for arg in cmdline.rstrip(b"\x00").split(b"\x00")]
    except (OSError, FileNotFoundError):
        pass
    step = get_github_step(pid)
    if step:
        result["step"] = step
    return result
