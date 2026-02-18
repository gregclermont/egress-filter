"""
Sudo management for the runner user.

Provides functions to disable/enable sudo by manipulating the sudoers file.
Used by the proxy at startup/shutdown and via control socket commands.
"""

import os
import shlex
from datetime import datetime, timezone

from . import logging as proxy_logging

SUDOERS_FILE = "/etc/sudoers.d/runner"
SUDOERS_BACKUP = os.environ.get("RUNNER_TEMP", "/tmp") + "/sudoers-runner-backup"
SUDO_LOG_FILE = os.environ.get("RUNNER_TEMP", "/tmp") + "/sudo.log"


def disable_sudo() -> tuple[bool, str]:
    """Disable sudo for the runner user by truncating the sudoers file.

    Returns (success, message).
    """
    try:
        if os.path.exists(SUDOERS_FILE):
            # Backup if not already done (in case allow-sudo was true initially)
            if not os.path.exists(SUDOERS_BACKUP):
                with open(SUDOERS_FILE, "r") as f:
                    content = f.read()
                with open(SUDOERS_BACKUP, "w") as f:
                    f.write(content)
            # Truncate to disable
            with open(SUDOERS_FILE, "w") as f:
                pass  # Empty file
            proxy_logging.logger.info("Sudo disabled for runner user")
            return True, "sudo disabled"
        else:
            return True, "sudoers file not found (sudo may already be disabled)"
    except Exception as e:
        proxy_logging.logger.error(f"Failed to disable sudo: {e}")
        return False, str(e)


def enable_sudo() -> tuple[bool, str]:
    """Re-enable sudo for the runner user by restoring from backup.

    Returns (success, message).
    """
    try:
        if os.path.exists(SUDOERS_BACKUP):
            with open(SUDOERS_BACKUP, "r") as f:
                content = f.read()
            with open(SUDOERS_FILE, "w") as f:
                f.write(content)
            proxy_logging.logger.info("Sudo re-enabled for runner user")
            return True, "sudo enabled"
        else:
            return False, "no backup found (sudo was never disabled?)"
    except Exception as e:
        proxy_logging.logger.error(f"Failed to enable sudo: {e}")
        return False, str(e)


def configure_sudo_logging() -> tuple[bool, str]:
    """Configure sudo to log commands when allow-sudo is enabled.

    Backs up the original sudoers file and appends a logfile directive.
    The backup ensures enable_sudo() can restore the original at shutdown.

    Returns (success, message).
    """
    try:
        if not os.path.exists(SUDOERS_FILE):
            return False, "sudoers file not found"

        # Backup original (same as disable_sudo, so enable_sudo can restore)
        if not os.path.exists(SUDOERS_BACKUP):
            with open(SUDOERS_FILE, "r") as f:
                content = f.read()
            with open(SUDOERS_BACKUP, "w") as f:
                f.write(content)

        # Append logging directive
        with open(SUDOERS_FILE, "a") as f:
            f.write(f'\nDefaults logfile="{SUDO_LOG_FILE}"\n')

        return True, f"logging to {SUDO_LOG_FILE}"
    except Exception as e:
        proxy_logging.logger.error(f"Failed to configure sudo logging: {e}")
        return False, str(e)


def parse_sudo_log() -> list[dict]:
    """Parse the sudo log file into connection-style event dicts.

    Returns a list of dicts suitable for passing to log_connection().
    """
    if not os.path.exists(SUDO_LOG_FILE):
        return []

    events = []
    try:
        with open(SUDO_LOG_FILE, "r") as f:
            # Sudo logfile uses multiline entries: continuation lines start
            # with whitespace. Join them before parsing.
            entries = _join_sudo_log_lines(f)
        for entry in entries:
            event = _parse_sudo_log_entry(entry)
            if event:
                events.append(event)
    except Exception as e:
        proxy_logging.logger.error(f"Failed to parse sudo log: {e}")

    return events


def _join_sudo_log_lines(lines) -> list[str]:
    """Join multiline sudo log entries into single strings.

    Sudo wraps long log lines; continuation lines start with whitespace.
    """
    entries = []
    current = None
    for line in lines:
        stripped = line.rstrip("\n")
        if not stripped:
            continue
        if stripped[0].isspace():
            # Continuation line
            if current is not None:
                current += " " + stripped.strip()
        else:
            if current is not None:
                entries.append(current)
            current = stripped
    if current is not None:
        entries.append(current)
    return entries


def _parse_sudo_log_entry(entry: str) -> dict | None:
    """Parse a single sudo log entry into an event dict.

    Sudo logfile format (may be on one line or wrapped across multiple):
      Feb 18 10:30:45 : runner : TTY=pts/0 ; PWD=/home/runner ; USER=root ; COMMAND=/usr/bin/apt-get install -y curl

    On GitHub runners (no TTY, NOPASSWD), the format may use *** for some fields:
      Feb 18 00:41:17 : runner : *** ; USER=root ; COMMAND=/usr/bin/whoami

    GitHub-hosted runners use UTC, so timestamps are interpreted as UTC.
    """
    # Split on " : " to get [timestamp, user, fields...]
    parts = entry.split(" : ", 2)
    if len(parts) < 3:
        return None

    ts_str = parts[0].strip()
    fields_str = parts[2].strip()

    # Parse timestamp (no year in sudo log, use current year)
    try:
        now = datetime.now(timezone.utc)
        ts = datetime.strptime(ts_str, "%b %d %H:%M:%S").replace(
            year=now.year, tzinfo=timezone.utc
        )
    except ValueError:
        return None

    # Parse key=value fields separated by " ; "
    # Some fields may be "***" (no TTY/PWD on GitHub runners), skip those
    fields = {}
    for field in fields_str.split(" ; "):
        field = field.strip()
        if "=" in field:
            key, _, value = field.partition("=")
            fields[key.strip()] = value.strip()

    command = fields.get("COMMAND")
    if not command:
        return None

    try:
        cmdline = shlex.split(command)
    except ValueError:
        cmdline = command.split()

    event = {
        "ts": ts.isoformat(timespec="milliseconds"),
        "type": "sudo",
        "cmdline": cmdline,
    }

    if "PWD" in fields:
        event["pwd"] = fields["PWD"]
    if "USER" in fields:
        event["target_user"] = fields["USER"]

    return event
