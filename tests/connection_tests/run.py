#!/usr/bin/env python3
"""Run connection tracking tests.

Usage: run.py [--connections-log=PATH] [--skip-docker]

Runs tests on host, in docker bridge mode, and docker host mode.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
GENERATE_SCRIPT = SCRIPT_DIR / "generate.py"
CHECK_SCRIPT = SCRIPT_DIR / "check.py"

# Docker image with Python for running tests in containers
DOCKER_IMAGE = "python:3.12-alpine"


def run_generate(test_suite: str, in_docker: str | None = None) -> Path:
    """Run the generator and return path to results file.

    Args:
        test_suite: "host", "bridge", or "hostmode"
        in_docker: None for host, "bridge" or "host" for docker network mode
    """
    results_file = Path(tempfile.mktemp(suffix=".json"))

    if in_docker is None:
        # Run on host
        proc = subprocess.run(
            [sys.executable, str(GENERATE_SCRIPT), f"--tests={test_suite}"],
            capture_output=True,
            text=True,
        )
    else:
        # Run in docker
        network_flag = f"--network={in_docker}"

        # Mount the test scripts into container
        proc = subprocess.run(
            [
                "docker", "run", "--rm",
                network_flag,
                "-v", f"{SCRIPT_DIR}:/tests:ro",
                "-w", "/tests",
                DOCKER_IMAGE,
                "python", "generate.py", f"--tests={test_suite}",
            ],
            capture_output=True,
            text=True,
        )

    if proc.returncode != 0:
        print(f"Generator failed (exit {proc.returncode}):", file=sys.stderr)
        print(f"stdout: {proc.stdout}", file=sys.stderr)
        print(f"stderr: {proc.stderr}", file=sys.stderr)
        sys.exit(1)

    if not proc.stdout.strip():
        print(f"Generator produced no output", file=sys.stderr)
        print(f"stderr: {proc.stderr}", file=sys.stderr)
        sys.exit(1)

    with open(results_file, "w") as f:
        f.write(proc.stdout)

    return results_file


def run_check(results_file: Path, connections_log: Path, src_ip_pattern: str | None = None) -> bool:
    """Run the checker and return True if all tests passed."""
    cmd = [sys.executable, str(CHECK_SCRIPT), str(results_file), str(connections_log)]
    if src_ip_pattern:
        cmd.append(f"--src-ip-pattern={src_ip_pattern}")

    proc = subprocess.run(cmd)
    return proc.returncode == 0


def main():
    parser = argparse.ArgumentParser(description="Run connection tracking tests")
    parser.add_argument(
        "--connections-log",
        type=Path,
        default=Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "connections.jsonl",
        help="Path to connections log",
    )
    parser.add_argument(
        "--skip-docker",
        action="store_true",
        help="Skip docker tests",
    )
    args = parser.parse_args()

    all_passed = True

    # Test 1: Host tests
    print("=" * 60)
    print("Running HOST tests")
    print("=" * 60)
    results = run_generate("host", in_docker=None)
    if not run_check(results, args.connections_log):
        all_passed = False
    results.unlink()
    print()

    if not args.skip_docker:
        # Test 2: Docker bridge mode
        print("=" * 60)
        print("Running DOCKER BRIDGE tests")
        print("=" * 60)
        results = run_generate("bridge", in_docker="bridge")
        if not run_check(results, args.connections_log):
            all_passed = False
        results.unlink()
        print()

        # Test 3: Docker host mode
        print("=" * 60)
        print("Running DOCKER HOST MODE tests")
        print("=" * 60)
        results = run_generate("hostmode", in_docker="host")
        # Host mode uses host IP, no specific pattern needed
        if not run_check(results, args.connections_log):
            all_passed = False
        results.unlink()
        print()

    # Summary
    print("=" * 60)
    if all_passed:
        print("ALL TEST SUITES PASSED")
        sys.exit(0)
    else:
        print("SOME TESTS FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
