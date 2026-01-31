"""
Control socket for authenticated shutdown.

The post-hook needs to signal the proxy to shutdown, but after disabling sudo,
it can't use normal mechanisms. This Unix socket provides authenticated shutdown:

1. Post-hook connects to /tmp/egress-filter-control.sock
2. Proxy gets peer PID via SO_PEERCRED
3. Proxy verifies the caller using exact matches on stable fields:
   - parent exe: /home/runner/actions-runner/cached/bin/Runner.Worker
   - cgroup: 0::/system.slice/hosted-compute-agent.service
   - exe: /home/runner/actions-runner/cached/externals/node24/bin/node
   - GITHUB_ACTION: matches value passed from pre-hook (supports custom step ids)
   - cmdline: contains "egress-filter" (path varies)
4. If verified, proxy initiates graceful shutdown

This prevents malicious user code from triggering early shutdown to restore sudo.
"""

import asyncio
import os
import socket
import struct

from . import logging as proxy_logging
from .proc import (
    read_exe,
    read_cmdline,
    read_environ,
    read_cgroup,
    read_ppid,
    get_process_ancestry,
)

CONTROL_SOCKET_PATH = "/tmp/egress-filter-control.sock"

# Exact expected values for stable fields (from actual GHA runner observation)
# Parent exe is completely stable - exact path to Runner.Worker
EXPECTED_PARENT_EXE = "/home/runner/actions-runner/cached/bin/Runner.Worker"

# Cgroup is stable for GHA hosted runners
EXPECTED_CGROUP = "0::/system.slice/hosted-compute-agent.service"

# Node exe - exact path, must match 'using' in action.yml (currently node24)
EXPECTED_EXE = "/home/runner/actions-runner/cached/externals/node24/bin/node"

# GITHUB_ACTION is passed from pre-hook via environment.
# Format varies: __<owner>_<repo> for default step id, or custom id if user specifies one.
# Captured at startup so post-hook verification uses the same value.
EXPECTED_GITHUB_ACTION = os.environ.get("GITHUB_ACTION", "")

# Cmdline can vary based on action path, but must contain our action
EXPECTED_CMDLINE_PATTERNS = [
    "egress-filter",  # Action name must appear in path
]


def get_peer_pid(sock: socket.socket) -> int | None:
    """Get the PID of the peer process via SO_PEERCRED."""
    try:
        # SO_PEERCRED returns (pid, uid, gid) as 3 ints
        cred = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", cred)
        return pid
    except Exception as e:
        proxy_logging.logger.warning(f"Failed to get peer credentials: {e}")
        return None


def collect_caller_info(pid: int) -> dict:
    """Collect all identity info for a caller process."""
    ppid = read_ppid(pid)
    info = {
        "pid": pid,
        "ppid": ppid,
        "exe": read_exe(pid),
        "parent_exe": read_exe(ppid) if ppid else "",
        "cgroup": read_cgroup(pid),
        "github_action": read_environ(pid).get("GITHUB_ACTION", ""),
        "cmdline": read_cmdline(pid),
    }
    ancestry = get_process_ancestry(pid)
    info["ancestry"] = " -> ".join(f"{p}({c})" for p, c in ancestry)
    return info


def log_caller_info(info: dict, prefix: str = ""):
    """Log all caller identity info."""
    proxy_logging.logger.info(
        f"{prefix}pid={info['pid']}, ppid={info['ppid']}, "
        f"exe={info['exe']}, parent_exe={info['parent_exe']}, "
        f"cgroup={info['cgroup']}, action={info['github_action']}, "
        f"cmdline={info['cmdline'][:200]}, ancestry={info['ancestry']}"
    )


def verify_caller(pid: int) -> tuple[bool, str]:
    """
    Verify that the calling process is our legitimate post-hook.

    Uses exact matches for stable fields:
    - parent exe: exact path to Runner.Worker
    - cgroup: exact GHA hosted runner cgroup
    - exe: exact node path
    - GITHUB_ACTION: exact env var value

    Returns (is_valid, reason).
    """
    # Collect all info upfront for logging
    info = collect_caller_info(pid)

    # 1. Check parent exe (exact match - most stable)
    if info["parent_exe"] != EXPECTED_PARENT_EXE:
        log_caller_info(info, "REJECTED: ")
        return False, "parent_exe mismatch"

    # 2. Check cgroup (exact match)
    if info["cgroup"] != EXPECTED_CGROUP:
        log_caller_info(info, "REJECTED: ")
        return False, "cgroup mismatch"

    # 3. Check exe path (exact match)
    if info["exe"] != EXPECTED_EXE:
        log_caller_info(info, "REJECTED: ")
        return False, "exe mismatch"

    # 4. Check GITHUB_ACTION env var (exact match)
    if info["github_action"] != EXPECTED_GITHUB_ACTION:
        log_caller_info(info, "REJECTED: ")
        return False, "GITHUB_ACTION mismatch"

    # 5. Check cmdline contains our action (path can vary)
    cmdline_match = any(pattern in info["cmdline"] for pattern in EXPECTED_CMDLINE_PATTERNS)
    if not cmdline_match:
        log_caller_info(info, "REJECTED: ")
        return False, "cmdline mismatch"

    log_caller_info(info, "VERIFIED: ")
    return True, "verified"


class ControlServer:
    """Unix socket server for authenticated control commands."""

    def __init__(self, shutdown_callback):
        """
        Args:
            shutdown_callback: Async function to call for graceful shutdown
        """
        self.shutdown_callback = shutdown_callback
        self.server = None
        self.socket_path = CONTROL_SOCKET_PATH

    async def start(self):
        """Start the control socket server."""
        # Remove existing socket file
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

        # Create Unix socket server
        self.server = await asyncio.start_unix_server(
            self._handle_client,
            path=self.socket_path
        )

        # Make socket world-writable so runner user can connect
        os.chmod(self.socket_path, 0o666)

        proxy_logging.logger.info(f"Control socket listening on {self.socket_path}")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a control socket connection."""
        try:
            # Get the underlying socket for SO_PEERCRED
            sock = writer.get_extra_info("socket")
            if not sock:
                proxy_logging.logger.warning("Control socket: couldn't get socket object")
                writer.close()
                return

            # Get peer PID
            pid = get_peer_pid(sock)
            if pid is None:
                proxy_logging.logger.warning("Control socket: couldn't get peer PID")
                writer.write(b"error: couldn't identify caller\n")
                await writer.drain()
                writer.close()
                return

            # Read command (simple protocol: one line)
            try:
                data = await asyncio.wait_for(reader.readline(), timeout=5.0)
                command = data.decode("utf-8").strip()
            except asyncio.TimeoutError:
                proxy_logging.logger.warning(f"Control socket: timeout reading from pid={pid}")
                writer.close()
                return

            proxy_logging.logger.info(f"Control socket: received '{command}' from pid={pid}")

            if command == "shutdown":
                # Verify the caller is legitimate
                is_valid, reason = verify_caller(pid)

                if is_valid:
                    writer.write(b"ok: shutdown initiated\n")
                    await writer.drain()
                    writer.close()

                    # Trigger shutdown
                    proxy_logging.logger.info("Control socket: initiating authenticated shutdown")
                    await self.shutdown_callback()
                else:
                    proxy_logging.logger.warning(f"Control socket: rejected shutdown from pid={pid}: {reason}")
                    writer.write(f"error: unauthorized ({reason})\n".encode())
                    await writer.drain()
                    writer.close()
            else:
                writer.write(b"error: unknown command\n")
                await writer.drain()
                writer.close()

        except Exception as e:
            proxy_logging.logger.error(f"Control socket error: {e}")
            try:
                writer.close()
            except Exception:
                pass

    async def stop(self):
        """Stop the control socket server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()

        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass
