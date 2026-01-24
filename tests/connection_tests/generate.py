#!/usr/bin/env python3
"""Generate test connections.

Usage: generate.py [--tests=host|bridge|hostmode]

Runs the specified test suite and outputs JSON results to stdout.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

from tests import HOST_TESTS, BRIDGE_TESTS, HOSTMODE_TESTS

SCRIPT_DIR = Path(__file__).parent
MAKE_CONNECTION = SCRIPT_DIR / "make_connection.py"


def run_tests(test_suite: list) -> list:
    """Run a test suite and return results."""
    results = []

    for marker, conn_type, target, expect_logged, description in test_suite:
        # Run make_connection.py as subprocess
        # The marker appears early in cmdline for easy grep
        try:
            proc = subprocess.run(
                [sys.executable, str(MAKE_CONNECTION), marker, conn_type, target],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                result = json.loads(proc.stdout.strip())
            else:
                result = {
                    "marker": marker,
                    "type": conn_type,
                    "target": target,
                    "success": False,
                    "error": proc.stderr or "No output",
                }
        except subprocess.TimeoutExpired:
            result = {
                "marker": marker,
                "type": conn_type,
                "target": target,
                "success": False,
                "error": "Timeout",
            }
        except Exception as e:
            result = {
                "marker": marker,
                "type": conn_type,
                "target": target,
                "success": False,
                "error": str(e),
            }

        result["expect_logged"] = expect_logged
        result["description"] = description
        results.append(result)

    return results


def main():
    parser = argparse.ArgumentParser(description="Generate test connections")
    parser.add_argument(
        "--tests",
        choices=["host", "bridge", "hostmode"],
        default="host",
        help="Test suite to run",
    )
    args = parser.parse_args()

    suites = {
        "host": HOST_TESTS,
        "bridge": BRIDGE_TESTS,
        "hostmode": HOSTMODE_TESTS,
    }

    results = run_tests(suites[args.tests])
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
