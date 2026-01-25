#!/usr/bin/env python3
"""Command-line utility to validate egress filter policies in workflow YAML files.

Usage:
    python -m proxy.policy.cli <workflow.yml> [--strict]

Exit codes:
    0 - Valid policy (or no policy found)
    1 - Invalid policy (parse errors found)
    2 - File not found or invalid YAML
"""

import argparse
import logging
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print(
        "Error: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr
    )
    sys.exit(2)

from parsimonious.exceptions import ParseError

from .parser import GRAMMAR, PolicyVisitor, parse_policy, rule_to_dict


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


def main():
    parser = argparse.ArgumentParser(
        description="Validate egress filter policies in GitHub Actions workflow files.",
        epilog="Exit codes: 0=valid, 1=invalid policy, 2=file/YAML error",
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
        help="Show valid rules as well as errors",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Only output errors, no summary"
    )
    parser.add_argument(
        "--dump-rules",
        action="store_true",
        help="Output all parsed rules as JSON to stdout",
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
        import json

        all_rules = []
        for location, policy_text in policies:
            rules = parse_policy(policy_text)
            for rule in rules:
                all_rules.append(rule_to_dict(rule))
        print(json.dumps(all_rules, indent=2))
        sys.exit(0)

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
