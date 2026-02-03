#!/usr/bin/env python3
"""
Unified egress proxy with mitmproxy (TCP/DNS) and netfilterqueue (UDP).

Handles:
- TCP/HTTP/HTTPS: mitmproxy transparent mode
- DNS (UDP:53): mitmproxy DNS mode
- Other UDP: netfilterqueue logging (accept all for now)

All traffic is attributed to PIDs via BPF maps.
"""

import asyncio
import atexit
import os
import signal
import sys

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from .bpf import BPFState
from .control import ControlServer
from .sudo import disable_sudo, enable_sudo
from .handlers import MitmproxyAddon, NfqueueHandler
from .policy import PolicyEnforcer
from .policy.gha import validate_runner_environment
from . import logging as proxy_logging

# Graceful shutdown timeout (seconds)
SHUTDOWN_TIMEOUT = 3.0


async def run_mitmproxy(bpf: BPFState, enforcer: PolicyEnforcer):
    """Run mitmproxy with our addon."""
    proxy_logging.logger.info("Initializing mitmproxy...")
    master = None
    try:
        opts = Options(
            mode=["transparent", "dns@8053"],
            showhost=True,
        )
        master = DumpMaster(opts)
        master.addons.add(MitmproxyAddon(bpf, enforcer))
        proxy_logging.logger.info("Starting mitmproxy on port 8080 (TCP) and 8053 (DNS)...")
        await master.run()
    except asyncio.CancelledError:
        proxy_logging.logger.info("mitmproxy cancelled")
        raise  # Must re-raise for proper task cancellation
    except Exception as e:
        proxy_logging.logger.error(f"mitmproxy failed: {e}")
        import traceback
        proxy_logging.logger.error(traceback.format_exc())
        raise
    finally:
        if master:
            proxy_logging.logger.info("Shutting down mitmproxy master...")
            master.shutdown()


async def run_nfqueue(handler: NfqueueHandler):
    """Run nfqueue handler integrated with asyncio."""
    if not handler.setup():
        return

    fd = handler.get_fd()
    if fd is None:
        return

    loop = asyncio.get_event_loop()
    loop.add_reader(fd, handler.process_pending)

    proxy_logging.logger.info("nfqueue handler running")
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        proxy_logging.logger.info("nfqueue cancelled")
    finally:
        loop.remove_reader(fd)
        handler.cleanup()


def log_all_tasks(prefix: str = ""):
    """Log status of all asyncio tasks."""
    tasks = asyncio.all_tasks()
    proxy_logging.logger.info(f"{prefix}Active asyncio tasks: {len(tasks)}")
    for task in tasks:
        proxy_logging.logger.info(f"  Task '{task.get_name()}': done={task.done()}, cancelled={task.cancelled()}")


async def shutdown_tasks(tasks: list, timeout: float = SHUTDOWN_TIMEOUT):
    """Cancel tasks and wait for them to finish with timeout."""
    # Cancel all tasks
    for task in tasks:
        if not task.done():
            proxy_logging.logger.info(f"Cancelling task: {task.get_name()}")
            task.cancel()

    if not tasks:
        return

    # Wait for tasks to finish with timeout
    try:
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=timeout
        )
        for task, result in zip(tasks, results):
            if isinstance(result, asyncio.CancelledError):
                proxy_logging.logger.info(f"Task {task.get_name()} cancelled")
            elif isinstance(result, Exception):
                proxy_logging.logger.warning(f"Task {task.get_name()} ended with error: {result}")
            else:
                proxy_logging.logger.info(f"Task {task.get_name()} ended cleanly")
    except asyncio.TimeoutError:
        proxy_logging.logger.warning(f"Shutdown timed out after {timeout}s, some tasks may not have cleaned up")
        log_all_tasks("After timeout: ")


async def async_main():
    """Async main entry point."""
    proxy_logging.logger.info("=" * 50)
    proxy_logging.logger.info("Unified Proxy Starting")
    proxy_logging.logger.info(f"PID: {os.getpid()}")
    proxy_logging.logger.info("=" * 50)

    # Validate runner environment before proceeding
    env_errors = validate_runner_environment()
    if env_errors:
        for err in env_errors:
            proxy_logging.logger.error(f"Runner environment validation failed: {err}")
        proxy_logging.logger.error(
            "GitHub runner layout may have changed. Please report this issue."
        )
        sys.exit(1)

    # Setup BPF
    bpf = BPFState()
    bpf.setup()

    # Register cleanup
    def cleanup():
        proxy_logging.logger.info("atexit: cleaning up...")
        bpf.cleanup()
        proxy_logging.close_logging()
    atexit.register(cleanup)

    # Setup signal handlers
    loop = asyncio.get_event_loop()
    stop_event = asyncio.Event()

    def signal_handler(signum):
        sig_name = signal.Signals(signum).name
        proxy_logging.logger.info(f"Received signal {sig_name} ({signum})")
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        loop.add_signal_handler(sig, lambda s=sig: signal_handler(s))

    # Create control socket for authenticated shutdown
    async def trigger_shutdown():
        proxy_logging.logger.info("Authenticated shutdown triggered via control socket")
        stop_event.set()

    control_server = ControlServer(trigger_shutdown)
    await control_server.start()

    # Disable sudo unless allow-sudo is set
    allow_sudo = os.environ.get("EGRESS_ALLOW_SUDO", "0") == "1"
    if not allow_sudo:
        success, message = disable_sudo()
        if success:
            proxy_logging.logger.info(f"Sudo disabled: {message}")
        else:
            proxy_logging.logger.warning(f"Failed to disable sudo: {message}")
    else:
        proxy_logging.logger.info("Sudo left enabled (allow-sudo: true)")

    # Load policy and create enforcer
    policy_file = os.environ.get("EGRESS_POLICY_FILE", "")
    audit_mode = os.environ.get("EGRESS_AUDIT_MODE", "0") == "1"
    github_repository = os.environ.get("GITHUB_REPOSITORY", "")

    policy_text = ""
    if policy_file and os.path.exists(policy_file):
        with open(policy_file) as f:
            policy_text = f.read()
        # Don't delete - needed if proxy restarts
        proxy_logging.logger.info(f"Loaded policy from {policy_file} ({len(policy_text)} bytes)")
    else:
        proxy_logging.logger.info("No policy file, using empty policy")

    enforcer = PolicyEnforcer.for_runner(
        policy_text,
        audit_mode=audit_mode,
        github_repository=github_repository or None,
    )
    proxy_logging.logger.info(f"Policy enforcer created (audit_mode={audit_mode})")

    # Create tasks
    nfqueue_handler = NfqueueHandler(bpf, enforcer)
    mitmproxy_task = asyncio.create_task(run_mitmproxy(bpf, enforcer), name="mitmproxy")
    nfqueue_task = asyncio.create_task(run_nfqueue(nfqueue_handler), name="nfqueue")
    tasks = [mitmproxy_task, nfqueue_task]

    try:
        # Wait for stop signal OR task failure
        stop_task = asyncio.create_task(stop_event.wait(), name="stop_signal")
        done, _ = await asyncio.wait(
            [stop_task, mitmproxy_task, nfqueue_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        # Check what triggered the exit
        for task in done:
            if task != stop_task and task.exception():
                proxy_logging.logger.error(f"Task {task.get_name()} failed: {task.exception()}")

    finally:
        # Always cleanup, even on exception
        proxy_logging.logger.info("Shutting down...")
        stop_task.cancel()  # Cancel the stop_event.wait() task
        await shutdown_tasks(tasks)

        # Stop control socket
        await control_server.stop()

        # Restore sudo so post-hook can call proxy.sh stop
        enable_sudo()

        # Cleanup BPF (also handled by atexit as fallback)
        atexit.unregister(cleanup)
        bpf.cleanup()
        proxy_logging.close_logging()
        proxy_logging.logger.info("Shutdown complete")
        proxy_logging.logger.info("=" * 50)


def main():
    """Main entry point."""
    proxy_logging.init_logging()
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        proxy_logging.logger.info("Interrupted by user")
    except Exception as e:
        proxy_logging.logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
