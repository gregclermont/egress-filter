"""
Sudo management for the runner user.

Provides functions to disable/enable sudo by manipulating the sudoers file.
Used by the proxy at startup/shutdown and via control socket commands.
"""

import os

from . import logging as proxy_logging

SUDOERS_FILE = "/etc/sudoers.d/runner"
SUDOERS_BACKUP = os.environ.get("RUNNER_TEMP", "/tmp") + "/sudoers-runner-backup"


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
