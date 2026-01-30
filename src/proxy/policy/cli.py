#!/usr/bin/env python3
"""Command-line utility to validate egress filter policies in workflow YAML files.

Usage:
    python -m proxy.policy <workflow.yml> [--strict]
    python -m proxy.policy <workflow.yml> --analyze-log <connections.jsonl>

Exit codes:
    0 - Valid policy (or all connections allowed in analyze mode)
    1 - Invalid policy (or some connections blocked in analyze mode)
    2 - File not found or invalid YAML/JSON
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    print(
        "Error: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr
    )
    sys.exit(2)

from parsimonious.exceptions import ParseError

from .defaults import PRESETS, get_defaults
from .dns_cache import DNSIPCache
from .enforcer import PolicyEnforcer, ProcessInfo
from .matcher import ConnectionEvent, PolicyMatcher
from .parser import GRAMMAR, PolicyVisitor, parse_policy, rule_to_dict
from .defaults import RUNNER_DEFAULTS
from .types import DefaultContext


def find_policies_in_workflow(workflow: dict) -> list[tuple[str, str]]:
    """Find all egress-filter policy definitions in a workflow.

    Returns list of (location, policy_text) tuples.
    """
    policies = []

    jobs = workflow.get("jobs", {})
    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for i, step in enumerate(steps):
            uses = step.get("uses", "")
            # Match egress-filter action (any owner, any version)
            if "egress-filter@" in uses or uses.endswith("/egress-filter"):
                with_block = step.get("with", {})
                policy = with_block.get("policy")
                if policy:
                    step_name = step.get("name", f"step {i}")
                    location = f"jobs.{job_name}.steps[{i}] ({step_name})"
                    policies.append((location, policy))

    return policies


def validate_policy(policy_text: str) -> list[tuple[int, str, str]]:
    """Validate a policy and return list of (line_num, line, error) for invalid lines."""
    errors = []
    visitor = PolicyVisitor()

    for line_num, line in enumerate(policy_text.splitlines(), start=1):
        line_stripped = line.strip()

        # Skip empty lines and comments
        if not line_stripped or line_stripped.startswith("#"):
            continue

        try:
            tree = GRAMMAR.parse(line)
            visitor.rules = []
            visitor.visit(tree)
        except ParseError as e:
            errors.append((line_num, line_stripped, str(e)))

    return errors


def connection_key(conn: dict) -> tuple:
    """Generate a deduplication key for a connection."""
    conn_type = conn.get("type", "")

    if conn_type == "http":
        # For HTTP, group by method + URL (without query params)
        return (conn_type, conn.get("method", "GET"), conn.get("url", ""))
    elif conn_type == "https":
        return (conn_type, conn.get("host", ""), conn.get("dst_port", 443))
    elif conn_type == "dns":
        return (conn_type, conn.get("name", ""), conn.get("dst_port", 53))
    elif conn_type == "tcp":
        # For TCP, include host if available (from DNS correlation), else IP
        host = conn.get("host", conn.get("dst_ip", ""))
        return (conn_type, host, conn.get("dst_port", 0))
    elif conn_type == "udp":
        return (conn_type, conn.get("dst_ip", ""), conn.get("dst_port", 0))
    else:
        # Fallback
        return (conn_type, conn.get("dst_ip", ""), conn.get("dst_port", 0))


def format_connection(conn: dict) -> str:
    """Format a connection for human-readable output."""
    conn_type = conn.get("type", "unknown")

    if conn_type == "http":
        method = conn.get("method", "GET")
        url = conn.get("url", "")
        return f"{method} {url}"
    elif conn_type == "https":
        host = conn.get("host", conn.get("dst_ip", "unknown"))
        port = conn.get("dst_port", 443)
        if port == 443:
            return f"https://{host}"
        return f"https://{host}:{port}"
    elif conn_type == "dns":
        name = conn.get("name", "unknown")
        server = conn.get("dst_ip", "")
        return f"dns:{name} (via {server})"
    elif conn_type == "tcp":
        host = conn.get("host", conn.get("dst_ip", "unknown"))
        port = conn.get("dst_port", 0)
        return f"tcp://{host}:{port}"
    elif conn_type == "udp":
        ip = conn.get("dst_ip", "unknown")
        port = conn.get("dst_port", 0)
        return f"udp://{ip}:{port}"
    else:
        return f"{conn_type}://{conn.get('dst_ip', '?')}:{conn.get('dst_port', '?')}"


def analyze_connections(
    policy_text: str,
    connections: list[dict],
    defaults: DefaultContext | None = None,
) -> dict:
    """Analyze connections against a policy.

    Args:
        policy_text: The policy text to parse.
        connections: List of connection dicts from the log.
        defaults: Optional DefaultContext for parsing (e.g., RUNNER_DEFAULTS).

    Returns dict with 'allowed' and 'blocked' lists, each containing
    (connection, count, rule_info) tuples.
    """
    matcher = PolicyMatcher(policy_text, defaults=defaults)
    dns_cache = DNSIPCache()
    enforcer = PolicyEnforcer(matcher, dns_cache)

    # Deduplicate and count connections
    conn_counts: dict[tuple, dict] = {}  # key -> {conn, count}

    for conn in connections:
        key = connection_key(conn)
        if key not in conn_counts:
            conn_counts[key] = {"conn": conn, "count": 0}
        conn_counts[key]["count"] += 1

    allowed = []
    blocked = []

    for key, data in conn_counts.items():
        conn = data["conn"]
        count = data["count"]

        # Create ConnectionEvent from log entry
        event = ConnectionEvent.from_dict(conn)

        # Check against policy
        is_allowed, rule_idx = matcher.match(event)

        if is_allowed:
            rule_info = f"rule {rule_idx}" if rule_idx is not None else "unknown"
            allowed.append((conn, count, rule_info))
        else:
            blocked.append((conn, count, None))

    return {"allowed": allowed, "blocked": blocked}


def print_analysis_results(results: dict, verbose: bool = False) -> int:
    """Print analysis results in human-readable format.

    Returns exit code (0 if all allowed, 1 if any blocked).
    """
    blocked = results["blocked"]
    allowed = results["allowed"]

    # Always show blocked connections (this is what users care about most)
    if blocked:
        print("BLOCKED connections (would fail with this policy):")
        print("-" * 60)
        for conn, count, _ in sorted(blocked, key=lambda x: format_connection(x[0])):
            formatted = format_connection(conn)
            count_str = f" (x{count})" if count > 1 else ""

            # Show process info if available
            exe = conn.get("exe", "")
            step = conn.get("step", "")
            context_parts = []
            if exe:
                context_parts.append(f"exe={exe}")
            if step:
                context_parts.append(f"step={step}")
            context = f"  [{', '.join(context_parts)}]" if context_parts else ""

            print(f"  {formatted}{count_str}{context}")
        print()

    # Show allowed connections only in verbose mode
    if verbose and allowed:
        print("ALLOWED connections:")
        print("-" * 60)
        for conn, count, rule_info in sorted(
            allowed, key=lambda x: format_connection(x[0])
        ):
            formatted = format_connection(conn)
            count_str = f" (x{count})" if count > 1 else ""
            print(f"  {formatted}{count_str}  <- {rule_info}")
        print()

    # Summary
    total = len(blocked) + len(allowed)
    print(
        f"Summary: {len(allowed)} allowed, {len(blocked)} blocked (out of {total} unique connections)"
    )

    if blocked:
        print("\nTo allow blocked connections, add rules for them to your policy.")
        return 1
    else:
        print("\nAll connections would be allowed by this policy.")
        return 0


def load_connections_log(log_path: Path) -> list[dict]:
    """Load connections from a JSONL log file."""
    connections = []
    with open(log_path) as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                conn = json.loads(line)
                connections.append(conn)
            except json.JSONDecodeError as e:
                print(f"Warning: Invalid JSON on line {line_num}: {e}", file=sys.stderr)
    return connections


def main():
    parser = argparse.ArgumentParser(
        description="Validate egress filter policies in GitHub Actions workflow files.",
        epilog="Exit codes: 0=valid/all-allowed, 1=invalid/some-blocked, 2=file error",
    )
    parser.add_argument("workflow", type=Path, help="Path to workflow YAML file")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat any parse error as fatal (exit 1 on first error)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show valid rules (validate) or allowed connections (analyze)",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Only output errors, no summary"
    )
    parser.add_argument(
        "--dump-rules",
        action="store_true",
        help="Output all parsed rules as JSON to stdout",
    )
    parser.add_argument(
        "--analyze-log",
        type=Path,
        metavar="CONNECTIONS.jsonl",
        help="Analyze a connections log against the policy (test before deploying)",
    )
    parser.add_argument(
        "--include-defaults",
        action="store_true",
        help="Include GitHub Actions infrastructure defaults (local DNS, git, actions runner)",
    )
    parser.add_argument(
        "--include-preset",
        action="append",
        metavar="NAME",
        choices=list(PRESETS.keys()),
        help=f"Include a preset policy. Available: {', '.join(PRESETS.keys())}",
    )
    parser.add_argument(
        "--no-runner-cgroup",
        action="store_true",
        help="Disable the default runner cgroup constraint (for generic/non-runner use)",
    )

    args = parser.parse_args()

    # Read workflow file
    if not args.workflow.exists():
        print(f"Error: File not found: {args.workflow}", file=sys.stderr)
        sys.exit(2)

    try:
        with open(args.workflow) as f:
            workflow = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"Error: Invalid YAML: {e}", file=sys.stderr)
        sys.exit(2)

    if not isinstance(workflow, dict):
        print(f"Error: Workflow file is not a valid YAML mapping", file=sys.stderr)
        sys.exit(2)

    # Find policies
    policies = find_policies_in_workflow(workflow)

    if not policies:
        if not args.quiet:
            print(
                f"No egress-filter policies found in {args.workflow}", file=sys.stderr
            )
        if args.dump_rules:
            print("[]")
        sys.exit(0)

    # Handle --dump-rules mode
    if args.dump_rules:
        # Build combined policy from defaults, presets, and workflow policies
        policy_parts = []

        if args.include_defaults:
            policy_parts.append(get_defaults())

        if args.include_preset:
            for preset_name in args.include_preset:
                preset = PRESETS.get(preset_name)
                if preset:
                    policy_parts.append(preset)

        for _, policy_text in policies:
            policy_parts.append(policy_text)

        combined_policy = "\n".join(policy_parts)

        # Report syntax errors to stderr
        errors = validate_policy(combined_policy)
        if errors:
            for line_num, line, error in errors:
                print(f"Syntax error on line {line_num}: {line}", file=sys.stderr)
            print(file=sys.stderr)

        # Apply runner cgroup constraint by default (disable with --no-runner-cgroup)
        defaults = None if args.no_runner_cgroup else RUNNER_DEFAULTS

        all_rules = []
        for rule in parse_policy(combined_policy, defaults=defaults):
            all_rules.append(rule_to_dict(rule))
        print(json.dumps(all_rules, indent=2))
        sys.exit(1 if errors else 0)

    # Handle --analyze-log mode
    if args.analyze_log:
        if not args.analyze_log.exists():
            print(f"Error: Log file not found: {args.analyze_log}", file=sys.stderr)
            sys.exit(2)

        # Build combined policy from defaults, presets, and workflow policies
        policy_parts = []

        # Include defaults if requested
        if args.include_defaults:
            policy_parts.append(get_defaults())

        # Include presets if requested
        if args.include_preset:
            for preset_name in args.include_preset:
                preset = PRESETS.get(preset_name)
                if preset:
                    policy_parts.append(preset)

        # Add workflow policies
        for _, policy_text in policies:
            policy_parts.append(policy_text)

        combined_policy = "\n".join(policy_parts)

        # Report syntax errors to stderr
        errors = validate_policy(combined_policy)
        if errors:
            for line_num, line, error in errors:
                print(f"Syntax error on line {line_num}: {line}", file=sys.stderr)
            print(file=sys.stderr)

        # Load connections
        connections = load_connections_log(args.analyze_log)
        if not connections:
            print("No connections found in log file.", file=sys.stderr)
            sys.exit(0)

        # Apply runner cgroup constraint by default (disable with --no-runner-cgroup)
        defaults = None if args.no_runner_cgroup else RUNNER_DEFAULTS

        # Analyze
        results = analyze_connections(combined_policy, connections, defaults=defaults)
        exit_code = print_analysis_results(results, verbose=args.verbose)
        # Exit with error if there were syntax errors
        sys.exit(1 if errors else exit_code)

    # Validate each policy
    total_errors = 0
    total_rules = 0

    for location, policy_text in policies:
        errors = validate_policy(policy_text)

        # Count valid rules
        valid_lines = 0
        for line in policy_text.splitlines():
            line_stripped = line.strip()
            if line_stripped and not line_stripped.startswith("#"):
                valid_lines += 1
        valid_rules = valid_lines - len(errors)
        total_rules += valid_rules

        if errors:
            print(f"\n{args.workflow}: {location}")
            for line_num, line, error in errors:
                print(f"  line {line_num}: {line}")
                # Extract just the key part of the parse error
                if "Rule" in error:
                    # parsimonious errors are verbose, simplify
                    print(f"    ^ invalid syntax")
                else:
                    print(f"    ^ {error}")
                total_errors += 1

                if args.strict:
                    print(f"\nValidation failed (strict mode): {total_errors} error(s)")
                    sys.exit(1)

        if args.verbose and valid_rules > 0:
            print(f"\n{args.workflow}: {location}")
            print(f"  {valid_rules} valid rule(s)")

    # Summary
    if not args.quiet:
        if total_errors > 0:
            print(
                f"\nValidation failed: {total_errors} error(s), {total_rules} valid rule(s)"
            )
        else:
            print(f"\nValidation passed: {total_rules} rule(s)")

    sys.exit(1 if total_errors > 0 else 0)


if __name__ == "__main__":
    main()
