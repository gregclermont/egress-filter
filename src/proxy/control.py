"""
Control socket for authenticated commands.

The post-hook needs to signal the proxy to shutdown, but after disabling sudo,
it can't use normal mechanisms. This Unix socket provides authenticated commands:

1. Client connects to /tmp/egress-filter-control.sock
2. Proxy gets peer PID via SO_PEERCRED
3. Proxy verifies the caller:
   - Runner.Worker must be in process ancestry
   - cgroup must match hosted runner cgroup
   - GITHUB_ACTION_REPOSITORY must match (captured at startup)
4. If verified, proxy executes the command

Commands:
- shutdown: graceful proxy shutdown (used by post-hook)
- disable-sudo: disable sudo for runner user (used by disable-sudo sub-action)

This prevents malicious user code from triggering these sensitive operations.
"""

import asyncio
import os
import socket
import struct

from . import logging as proxy_logging
from .proc import (
    read_exe,
    read_cmdline,
    read_cgroup,
    read_ppid,
    get_process_ancestry,
    get_trusted_github_env,
)
from .sudo import disable_sudo, enable_sudo

CONTROL_SOCKET_PATH = "/tmp/egress-filter-control.sock"


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
    trusted_env = get_trusted_github_env(pid)
    ancestry = get_process_ancestry(pid)

    return {
        "pid": pid,
        "ppid": ppid,
        "exe": read_exe(pid),
        "parent_exe": read_exe(ppid) if ppid else "",
        "cgroup": read_cgroup(pid),
        "github_action": trusted_env.get("GITHUB_ACTION", ""),
        "github_action_repo": trusted_env.get("GITHUB_ACTION_REPOSITORY", ""),
        "cmdline": read_cmdline(pid),
        "ancestry": " -> ".join(f"{p}({exe})" for p, exe in ancestry),
    }


def log_caller_info(info: dict, prefix: str = ""):
    """Log all caller identity info."""
    proxy_logging.logger.info(
        f"{prefix}pid={info['pid']}, ppid={info['ppid']}, "
        f"exe={info['exe']}, parent_exe={info['parent_exe']}, "
        f"cgroup={info['cgroup']}, action={info['github_action']}, "
        f"action_repo={info['github_action_repo']}, "
        f"cmdline={info['cmdline'][:200]}, ancestry={info['ancestry']}"
    )


# Expected repo for verification. Captured at startup so forks work.
EXPECTED_ACTION_REPO = os.environ.get("GITHUB_ACTION_REPOSITORY", "")


def verify_caller(pid: int) -> tuple[bool, str]:
    """
    Verify the caller is from our action (or a fork).

    GITHUB_ACTION_REPOSITORY check implicitly validates:
    - Process is in runner cgroup
    - Runner.Worker is in ancestry
    - Env var matches our repo (captured at startup)

    Returns (is_valid, reason).
    """
    info = collect_caller_info(pid)

    if not info["github_action_repo"]:
        log_caller_info(info, "REJECTED: ")
        return False, "GITHUB_ACTION_REPOSITORY not found"

    if info["github_action_repo"] != EXPECTED_ACTION_REPO:
        log_caller_info(info, "REJECTED: ")
        return False, f"GITHUB_ACTION_REPOSITORY mismatch (got {info['github_action_repo']}, expected {EXPECTED_ACTION_REPO})"

    log_caller_info(info, "VERIFIED: ")
    return True, "verified"


async def _send_response(writer: asyncio.StreamWriter, success: bool, message: str):
    """Send response and close connection."""
    prefix = "ok" if success else "error"
    writer.write(f"{prefix}: {message}\n".encode())
    await writer.drain()
    writer.close()


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
                await _send_response(writer, False, "couldn't identify caller")
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

            # Verify the caller is legitimate for any command (strict: requires exact repo match)
            is_valid, reason = verify_caller(pid)

            if not is_valid:
                proxy_logging.logger.warning(f"Control socket: rejected '{command}' from pid={pid}: {reason}")
                await _send_response(writer, False, f"unauthorized ({reason})")
                return

            if command == "shutdown":
                await _send_response(writer, True, "shutdown initiated")
                proxy_logging.logger.info("Control socket: initiating authenticated shutdown")
                await self.shutdown_callback()

            elif command == "disable-sudo":
                success, message = disable_sudo()
                await _send_response(writer, success, message)

            elif command == "enable-sudo":
                success, message = enable_sudo()
                await _send_response(writer, success, message)

            else:
                await _send_response(writer, False, "unknown command")

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
