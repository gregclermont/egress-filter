#!/usr/bin/env python3
"""Check connection log against expected results.

Usage: check.py <results.json> <connections.jsonl> [--src-ip-pattern=PATTERN]

Verifies that each expected connection appears in the log with a PID.
"""

import argparse
import json
import re
import sys
from pathlib import Path


def load_results(path: Path) -> list:
    """Load generator results."""
    with open(path) as f:
        return json.load(f)


def load_connections(path: Path) -> list:
    """Load connection log (JSONL format)."""
    connections = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    connections.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return connections


def find_connection(connections: list, marker: str) -> dict | None:
    """Find a connection log entry by marker in cmdline."""
    for conn in connections:
        cmdline = conn.get("cmdline", [])
        # Marker should be in cmdline (as argument to make_connection.py)
        if marker in str(cmdline):
            return conn
    return None


def check_connection(conn: dict, expected: dict, src_ip_pattern: str | None) -> tuple[bool, str]:
    """Check if a connection entry meets expectations.

    Returns (passed, message).
    """
    # Must have a PID
    pid = conn.get("pid")
    if pid is None:
        return False, "No PID in log entry"

    # Check source IP pattern if specified
    if src_ip_pattern:
        src_ip = conn.get("src_ip", "")
        if not re.match(src_ip_pattern, src_ip):
            return False, f"src_ip '{src_ip}' doesn't match pattern '{src_ip_pattern}'"

    return True, "OK"


def main():
    parser = argparse.ArgumentParser(description="Check connection log")
    parser.add_argument("results", type=Path, help="Generator results JSON")
    parser.add_argument("connections", type=Path, help="Connection log JSONL")
    parser.add_argument(
        "--src-ip-pattern",
        help="Regex pattern for expected src_ip (e.g., '172\\.17\\.')",
    )
    args = parser.parse_args()

    results = load_results(args.results)
    connections = load_connections(args.connections)

    passed = 0
    failed = 0
    skipped = 0

    print(f"{'MARKER':<8} {'TYPE':<8} {'RESULT':<8} {'DETAILS'}")
    print("-" * 60)

    for expected in results:
        marker = expected["marker"]
        conn_type = expected["type"]
        expect_logged = expected.get("expect_logged", True)
        description = expected.get("description", "")

        # Find matching connection in log
        conn = find_connection(connections, marker)

        if not expect_logged:
            # Should NOT be in log
            if conn is None:
                print(f"{marker:<8} {conn_type:<8} {'PASS':<8} Not logged (expected)")
                passed += 1
            else:
                print(f"{marker:<8} {conn_type:<8} {'FAIL':<8} Found in log but shouldn't be")
                failed += 1
            continue

        if conn is None:
            print(f"{marker:<8} {conn_type:<8} {'FAIL':<8} Not found in log")
            failed += 1
            continue

        # Check the connection entry
        ok, msg = check_connection(conn, expected, args.src_ip_pattern)
        if ok:
            print(f"{marker:<8} {conn_type:<8} {'PASS':<8} {msg}")
            passed += 1
        else:
            print(f"{marker:<8} {conn_type:<8} {'FAIL':<8} {msg}")
            failed += 1

    print("-" * 60)
    print(f"Total: {passed + failed + skipped} | Passed: {passed} | Failed: {failed} | Skipped: {skipped}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
