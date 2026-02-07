#!/usr/bin/env python3
"""Command-line utility for egress filter management.

Usage:
    egress-filter validate <workflow.yml> [--strict] [--dump-rules]
    egress-filter analyze <workflow.yml> <connections.jsonl>
    egress-filter permissions <connections.jsonl>

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
from urllib.parse import urlparse

import yaml

from parsimonious.exceptions import ParseError

from .policy.defaults import PRESETS, get_defaults, RUNNER_DEFAULTS
from .policy.dns_cache import DNSIPCache
from .policy.enforcer import PolicyEnforcer, ProcessInfo
from .policy.matcher import ConnectionEvent, PolicyMatcher
from .policy.parser import (
    GRAMMAR,
    PolicyVisitor,
    parse_github_repository,
    parse_policy,
    rule_to_dict,
    substitute_placeholders,
    validate_policy,
)
from .policy.types import DefaultContext


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


def connection_key(conn: dict) -> tuple:
    """Generate a deduplication key for a connection."""
    conn_type = conn.get("type", "")

    if conn_type == "http":
        # For HTTP, group by method + URL (without query params)
        return (conn_type, conn.get("method", "GET"), conn.get("url", ""))
    elif conn_type == "https":
        if conn.get("url"):
            # MITMed HTTPS: proxy decrypted TLS and has full URL — key like HTTP
            return (conn_type, conn.get("method", "GET"), conn.get("url", ""))
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
        if conn.get("url"):
            # MITMed HTTPS: proxy decrypted TLS and has full URL
            method = conn.get("method", "GET")
            url = conn.get("url", "")
            return f"{method} {url}"
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

    Uses the same PolicyEnforcer logic as the live proxy to ensure consistent
    behavior between CLI analysis and runtime enforcement.

    Args:
        policy_text: The policy text to parse.
        connections: List of connection dicts from the log.
        defaults: Optional DefaultContext for parsing (e.g., RUNNER_DEFAULTS).

    Returns dict with 'allowed', 'blocked', and 'errors' lists, each containing
    (connection, count, rule_info) tuples. Error events (e.g., TLS failures)
    are separated since they represent connection failures, not policy decisions.
    """
    matcher = PolicyMatcher(policy_text, defaults=defaults)
    dns_cache = DNSIPCache()
    enforcer = PolicyEnforcer(matcher, dns_cache)

    # Pre-populate DNS cache from connection data.
    # This enables TCP connections to the same IPs to match hostname rules,
    # similar to how the live proxy correlates DNS responses with later connections.
    for conn in connections:
        # Use dns_response events (resolved IPs from actual DNS answers)
        if conn.get("type") == "dns_response":
            answers = conn.get("answers", [])
            name = conn.get("name")
            if name and answers:
                for ip in answers:
                    dns_cache.add(ip, name, ttl=3600)
            continue
        # Also use HTTPS/HTTP connections that have hostname info
        dst_ip = conn.get("dst_ip")
        host = conn.get("host")  # SNI for HTTPS
        if dst_ip and host:
            dns_cache.add(dst_ip, host, ttl=3600)
        url = conn.get("url")
        if dst_ip and url:
            parsed = urlparse(url)
            if parsed.hostname:
                dns_cache.add(dst_ip, parsed.hostname, ttl=3600)

    # Deduplicate and count connections, separating errors
    conn_counts: dict[tuple, dict] = {}  # key -> {conn, count}
    error_counts: dict[tuple, dict] = {}  # key -> {conn, count}

    for conn in connections:
        # dns_response entries are metadata (resolved IPs), not connections to evaluate
        if conn.get("type") == "dns_response":
            continue
        key = connection_key(conn)
        if conn.get("error"):
            # Error events go to separate bucket
            if key not in error_counts:
                error_counts[key] = {"conn": conn, "count": 0}
            error_counts[key]["count"] += 1
        else:
            if key not in conn_counts:
                conn_counts[key] = {"conn": conn, "count": 0}
            conn_counts[key]["count"] += 1

    allowed = []
    blocked = []

    for key, data in conn_counts.items():
        conn = data["conn"]
        count = data["count"]
        conn_type = conn.get("type", "")

        # Build ProcessInfo from connection data
        proc = ProcessInfo(
            exe=conn.get("exe"),
            cmdline=conn.get("cmdline"),
            cgroup=conn.get("cgroup"),
            step=conn.get("step"),
            action=conn.get("action"),
        )

        # Use the same enforcer methods as the live proxy
        dst_ip = conn.get("dst_ip", "")
        dst_port = conn.get("dst_port", 0)

        if conn_type == "https" and conn.get("url"):
            # MITMed HTTPS: proxy decrypted TLS and evaluated as HTTP request.
            # Use check_http() to match runtime behavior.
            decision = enforcer.check_http(
                dst_ip=dst_ip,
                dst_port=dst_port,
                url=conn.get("url", ""),
                method=conn.get("method", "GET"),
                proc=proc,
            )
        elif conn_type == "https":
            decision = enforcer.check_https(
                dst_ip=dst_ip,
                dst_port=dst_port,
                sni=conn.get("host"),
                proc=proc,
            )
        elif conn_type == "http":
            decision = enforcer.check_http(
                dst_ip=dst_ip,
                dst_port=dst_port,
                url=conn.get("url", ""),
                method=conn.get("method", "GET"),
                proc=proc,
            )
        elif conn_type == "tcp":
            decision = enforcer.check_tcp(
                dst_ip=dst_ip,
                dst_port=dst_port,
                proc=proc,
            )
        elif conn_type == "dns":
            decision = enforcer.check_dns(
                dst_ip=dst_ip,
                dst_port=dst_port,
                query_name=conn.get("name", ""),
                proc=proc,
            )
        elif conn_type == "udp":
            decision = enforcer.check_udp(
                dst_ip=dst_ip,
                dst_port=dst_port,
                proc=proc,
            )
        else:
            # Unknown type - fall back to direct matcher
            event = ConnectionEvent.from_dict(conn)
            is_allowed, rule_idx = matcher.match(event)
            decision = type('Decision', (), {
                'allowed': is_allowed,
                'matched_rule': rule_idx
            })()

        if decision.allowed:
            rule_info = f"rule {decision.matched_rule}" if decision.matched_rule is not None else "unknown"
            allowed.append((conn, count, rule_info))
        else:
            blocked.append((conn, count, None))

    # Collect error events (not evaluated against policy)
    errors = [(data["conn"], data["count"], None) for data in error_counts.values()]

    return {"allowed": allowed, "blocked": blocked, "errors": errors}


def print_analysis_results(results: dict, verbose: bool = False) -> int:
    """Print analysis results in human-readable format.

    Returns exit code (0 if all allowed, 1 if any blocked).
    """
    blocked = results["blocked"]
    allowed = results["allowed"]
    errors = results.get("errors", [])

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

    # Always show error events (connection failures, not policy decisions)
    if errors:
        print("FAILED connections (TLS/connection errors - not policy decisions):")
        print("-" * 60)
        for conn, count, _ in sorted(errors, key=lambda x: format_connection(x[0])):
            formatted = format_connection(conn)
            count_str = f" (x{count})" if count > 1 else ""
            error = conn.get("error", "unknown")

            # Show process info if available
            exe = conn.get("exe", "")
            step = conn.get("step", "")
            context_parts = [f"error={error}"]
            if exe:
                context_parts.append(f"exe={exe}")
            if step:
                context_parts.append(f"step={step}")
            context = f"  [{', '.join(context_parts)}]"

            print(f"  {formatted}{count_str}{context}")
        print()

    # Summary
    total = len(blocked) + len(allowed) + len(errors)
    summary_parts = [f"{len(allowed)} allowed", f"{len(blocked)} blocked"]
    if errors:
        summary_parts.append(f"{len(errors)} failed")
    print(f"Summary: {', '.join(summary_parts)} (out of {total} unique connections)")

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


def build_combined_policy(
    policies: list[tuple[str, str]],
    include_defaults: bool = True,
    presets: list[str] | None = None,
    repo: str | None = None,
) -> str:
    """Build a combined policy from defaults, presets, and workflow policies.

    Args:
        policies: List of (location, policy_text) tuples from workflow.
        include_defaults: Whether to include GitHub Actions infrastructure defaults.
        presets: List of preset names to include.
        repo: OWNER/REPO string for {owner}/{repo} placeholder substitution.

    Returns:
        Combined policy text with placeholders substituted.
    """
    policy_parts = []

    if include_defaults:
        policy_parts.append(get_defaults())

    if presets:
        for preset_name in presets:
            preset = PRESETS.get(preset_name)
            if preset:
                policy_parts.append(preset)

    for _, policy_text in policies:
        policy_parts.append(policy_text)

    combined_policy = "\n".join(policy_parts)

    # Substitute {owner} and {repo} placeholders
    if repo:
        owner, repo_name = parse_github_repository(repo)
        combined_policy = substitute_placeholders(combined_policy, owner=owner, repo=repo_name)

    return combined_policy


def _load_workflow(path: Path) -> dict:
    """Load and validate a workflow YAML file."""
    if not path.exists():
        print(f"Error: File not found: {path}", file=sys.stderr)
        sys.exit(2)
    try:
        with open(path) as f:
            workflow = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"Error: Invalid YAML: {e}", file=sys.stderr)
        sys.exit(2)
    if not isinstance(workflow, dict):
        print(f"Error: Workflow file is not a valid YAML mapping", file=sys.stderr)
        sys.exit(2)
    return workflow


def _cmd_validate(args) -> None:
    """Handle the 'validate' subcommand."""
    workflow = _load_workflow(args.workflow)
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
        combined_policy = build_combined_policy(
            policies,
            include_defaults=not args.no_defaults,
            presets=args.include_preset,
            repo=args.repo,
        )

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

    # Validate each policy
    total_errors = 0
    total_rules = 0

    # Parse --repo for placeholder substitution
    owner, repo_name = parse_github_repository(args.repo) if args.repo else (None, None)

    for location, policy_text in policies:
        # Substitute placeholders before validation
        if args.repo:
            policy_text = substitute_placeholders(policy_text, owner=owner, repo=repo_name)

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


def _cmd_analyze(args) -> None:
    """Handle the 'analyze' subcommand."""
    log_path = args.log or args.log_flag
    if not log_path:
        print("Error: connection log required (positional or --log)", file=sys.stderr)
        sys.exit(2)
    args.log = log_path

    workflow = _load_workflow(args.workflow)
    policies = find_policies_in_workflow(workflow)

    if not policies:
        if not args.quiet:
            print(
                f"No egress-filter policies found in {args.workflow}", file=sys.stderr
            )
        sys.exit(0)

    if not args.log.exists():
        print(f"Error: Log file not found: {args.log}", file=sys.stderr)
        sys.exit(2)

    combined_policy = build_combined_policy(
        policies,
        include_defaults=not args.no_defaults,
        presets=args.include_preset,
        repo=args.repo,
    )

    # Report syntax errors to stderr
    errors = validate_policy(combined_policy)
    if errors:
        for line_num, line, error in errors:
            print(f"Syntax error on line {line_num}: {line}", file=sys.stderr)
        print(file=sys.stderr)

    # Load connections
    connections = load_connections_log(args.log)
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


def _cmd_permissions(args) -> None:
    """Handle the 'permissions' subcommand."""
    from .permissions import analyze_permissions, format_permissions_yaml

    if not args.log.exists():
        print(f"Error: Log file not found: {args.log}", file=sys.stderr)
        sys.exit(2)

    connections = load_connections_log(args.log)
    if not connections:
        print("No connections found in log file.", file=sys.stderr)
        sys.exit(0)

    result = analyze_permissions(connections)

    if not result["permissions"]:
        print("No GitHub API calls with GITHUB_TOKEN detected.")
        print(
            "\nNote: Token detection requires the proxy to have GITHUB_TOKEN"
            "\n(set automatically by GitHub Actions)."
        )
        sys.exit(0)

    print(format_permissions_yaml(result))

    if result["unknown"]:
        print("# Unrecognized API calls (may need manual review):", file=sys.stderr)
        for method, path in result["unknown"]:
            print(f"#   {method} {path}", file=sys.stderr)

    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="Egress filter policy tools.",
        epilog="Exit codes: 0=valid/all-allowed, 1=invalid/some-blocked, 2=file error",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Shared parser for policy-building options (used by validate + analyze)
    policy_parent = argparse.ArgumentParser(add_help=False)
    policy_parent.add_argument(
        "--no-defaults",
        action="store_true",
        help="Disable GitHub Actions infrastructure defaults",
    )
    policy_parent.add_argument(
        "--include-preset",
        action="append",
        metavar="NAME",
        choices=list(PRESETS.keys()),
        help=f"Include a preset policy. Available: {', '.join(PRESETS.keys())}",
    )
    policy_parent.add_argument(
        "--no-runner-cgroup",
        action="store_true",
        help="Disable the default runner cgroup constraint",
    )
    policy_parent.add_argument(
        "--repo",
        metavar="OWNER/REPO",
        help="Substitute {owner} and {repo} placeholders in policy",
    )

    # validate
    p_validate = subparsers.add_parser(
        "validate", parents=[policy_parent],
        help="Validate policy syntax in a workflow file",
    )
    p_validate.add_argument("workflow", type=Path, help="Path to workflow YAML file")
    p_validate.add_argument("--strict", action="store_true",
                            help="Exit on first error")
    p_validate.add_argument("-v", "--verbose", action="store_true",
                            help="Show valid rules")
    p_validate.add_argument("-q", "--quiet", action="store_true",
                            help="Only output errors")
    p_validate.add_argument("--dump-rules", action="store_true",
                            help="Output parsed rules as JSON")
    p_validate.set_defaults(func=_cmd_validate)

    # analyze
    p_analyze = subparsers.add_parser(
        "analyze", parents=[policy_parent],
        help="Test a policy against a connection log",
    )
    p_analyze.add_argument("workflow", type=Path, help="Path to workflow YAML file")
    p_analyze.add_argument("log", type=Path, nargs="?", default=None,
                           help="Path to connections JSONL log")
    p_analyze.add_argument("--log", type=Path, dest="log_flag", metavar="CONNECTIONS.jsonl",
                           help="Path to connections JSONL log (alternative to positional)")
    p_analyze.add_argument("-v", "--verbose", action="store_true",
                           help="Show allowed connections")
    p_analyze.add_argument("-q", "--quiet", action="store_true",
                           help="Only output errors")
    p_analyze.set_defaults(func=_cmd_analyze)

    # permissions
    p_permissions = subparsers.add_parser(
        "permissions",
        help="Analyze GitHub API token usage and recommend minimum permissions",
    )
    p_permissions.add_argument("log", type=Path, help="Path to connections JSONL log")
    p_permissions.set_defaults(func=_cmd_permissions)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
