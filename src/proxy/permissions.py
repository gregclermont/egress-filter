"""GitHub API permission analysis from connection logs.

Maps (HTTP method, API path) to GitHub Actions permission scopes.
Ported from GitHubSecurityLab/actions-permissions.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Permission mapping table
# ---------------------------------------------------------------------------
# Each entry: (method, path_suffix, scope, access)
# path_suffix is relative to /repos/{owner}/{repo}/ with dynamic segments
# replaced by "*". Also matches /repositories/{id}/ paths.
#
# Scope values:
#   "contents"              -> single scope
#   "issues/pull-requests"  -> ambiguous, needs disambiguation
#   "issues,pull-requests"  -> applies to both scopes
#
# Ported from GitHubSecurityLab/actions-permissions mitm_plugin.py

_EXPLICIT_MAP: list[tuple[str, str, str, str]] = [
    # contents
    ("GET", "codeowners/errors", "contents", "read"),
    ("PUT", "pulls/*/merge", "contents", "write"),
    ("PUT", "pulls/*/update-branch", "contents", "write"),
    ("POST", "comments/*/reactions", "contents", "write"),
    ("DELETE", "comments/*/reactions/*", "contents", "write"),
    ("GET", "branches", "contents", "read"),
    ("POST", "merge-upstream", "contents", "write"),
    ("POST", "merges", "contents", "write"),
    ("PATCH", "comments/*", "contents", "write"),
    ("DELETE", "comments/*", "contents", "write"),
    ("POST", "dispatches", "contents", "write"),
    # issues/pull-requests (ambiguous — needs disambiguation)
    ("POST", "issues/*/assignees", "issues/pull-requests", "write"),
    ("DELETE", "issues/*/assignees", "issues/pull-requests", "write"),
    ("GET", "issues/*/comments", "issues/pull-requests", "read"),
    ("POST", "issues/*/comments", "issues/pull-requests", "write"),
    ("GET", "issues/comments/*", "issues/pull-requests", "read"),
    ("PATCH", "issues/comments/*", "issues/pull-requests", "write"),
    ("DELETE", "issues/comments/*", "issues/pull-requests", "write"),
    ("GET", "issues/*/events", "issues/pull-requests", "read"),
    ("GET", "issues/events/*", "issues/pull-requests", "read"),
    ("GET", "issues/*/timeline", "issues/pull-requests", "read"),
    ("GET", "issues/*", "issues/pull-requests", "read"),
    ("PATCH", "issues/*", "issues/pull-requests", "write"),
    ("PUT", "issues/*/lock", "issues/pull-requests", "write"),
    ("DELETE", "issues/*/lock", "issues/pull-requests", "write"),
    ("GET", "issues/*/labels", "issues/pull-requests", "read"),
    ("POST", "issues/*/labels", "issues/pull-requests", "write"),
    ("PUT", "issues/*/labels", "issues/pull-requests", "write"),
    ("DELETE", "issues/*/labels", "issues/pull-requests", "write"),
    ("DELETE", "issues/*/labels/*", "issues/pull-requests", "write"),
    ("GET", "issues/*/reactions", "issues/pull-requests", "read"),
    ("POST", "issues/*/reactions", "issues/pull-requests", "write"),
    ("DELETE", "issues/*/reactions/*", "issues/pull-requests", "write"),
    ("GET", "issues/comments/*/reactions", "issues/pull-requests", "read"),
    ("POST", "issues/comments/*/reactions", "issues/pull-requests", "write"),
    ("DELETE", "issues/comments/*/reactions", "issues/pull-requests", "write"),
    # issues,pull-requests (applies to both scopes)
    ("GET", "issues/comments", "issues,pull-requests", "read"),
    ("GET", "issues/events", "issues,pull-requests", "read"),
    ("GET", "assignees", "issues,pull-requests", "read"),
    ("GET", "issues", "issues,pull-requests", "read"),
    # issues only
    ("POST", "issues", "issues", "write"),
    ("GET", "labels", "issues", "read"),
    ("POST", "labels", "issues", "write"),
    ("GET", "labels/*", "issues", "read"),
    ("PATCH", "labels/*", "issues", "write"),
    ("DELETE", "labels/*", "issues", "write"),
    ("GET", "milestones/*/labels", "issues", "read"),
    ("GET", "milestones", "issues", "read"),
    ("POST", "milestones", "issues", "write"),
    ("GET", "milestones/*", "issues", "read"),
    ("PATCH", "milestones/*", "issues", "write"),
    ("DELETE", "milestones/*", "issues", "write"),
]

# Pre-compile: split path suffixes into segment tuples for matching
_COMPILED_MAP: list[tuple[str, tuple[str, ...], str, str]] = [
    (method, tuple(path.split("/")), scope, access)
    for method, path, scope, access in _EXPLICIT_MAP
]

# Resource name -> permission scope (for pattern-based fallback)
_RESOURCE_SCOPE: dict[str, str] = {
    "actions": "actions",
    "check-runs": "checks",
    "check-suites": "checks",
    "pulls": "pull-requests",
    "releases": "contents",
    "git": "contents",
    "commits": "contents",
    "compare": "contents",
    "contents": "contents",
    "deployments": "deployments",
    "environments": "deployments",
    "pages": "pages",
    "code-scanning": "security-events",
    "secret-scanning": "security-events",
    "dependabot": "security-events",
    "statuses": "statuses",
    "projects": "projects",
    "packages": "packages",
}


# ---------------------------------------------------------------------------
# Path matching
# ---------------------------------------------------------------------------

def _strip_repo_prefix(path: str) -> tuple[str, ...] | None:
    """Strip /repos/{owner}/{repo}/ or /repositories/{id}/ prefix.

    Returns remaining path segments, or None if path doesn't match.
    """
    segments = [s for s in path.split("/") if s]
    if len(segments) >= 3 and segments[0] == "repos":
        # /repos/{owner}/{repo}/...
        return tuple(segments[3:])
    if len(segments) >= 2 and segments[0] == "repositories":
        # /repositories/{id}/...
        return tuple(segments[2:])
    return None


def _segments_match(pattern: tuple[str, ...], actual: tuple[str, ...]) -> bool:
    """Check if path segments match a pattern (with * wildcards)."""
    if len(pattern) != len(actual):
        return False
    return all(p == "*" or p == a for p, a in zip(pattern, actual))


def match_permission(method: str, path: str) -> list[tuple[str, str]]:
    """Match a GitHub API request to permission scopes.

    Args:
        method: HTTP method (GET, POST, PATCH, PUT, DELETE)
        path: URL path (e.g., "/repos/owner/repo/issues/1/comments")

    Returns:
        List of (scope, access_level) tuples. May return:
        - Single tuple for unambiguous matches
        - Multiple tuples for "both" scopes (issues,pull-requests)
        - [("unknown", "unknown")] for unrecognized endpoints
    """
    suffix = _strip_repo_prefix(path)
    if suffix is None:
        return [("unknown", "unknown")]

    if not suffix:
        # /repos/{owner}/{repo} itself — no specific permission needed
        return []

    method = method.upper()

    # 1. Try explicit map — prefer exact matches over wildcard matches
    best_match = None
    best_wildcards = None
    for pat_method, pat_segments, scope, access in _COMPILED_MAP:
        if pat_method == method and _segments_match(pat_segments, suffix):
            wildcards = sum(1 for s in pat_segments if s == "*")
            if best_wildcards is None or wildcards < best_wildcards:
                best_match = (scope, access)
                best_wildcards = wildcards
                if wildcards == 0:
                    break  # Exact match, can't do better

    if best_match is not None:
        scope, access = best_match
        if "," in scope:
            return [(s, access) for s in scope.split(",")]
        return [(scope, access)]

    # 2. Pattern-based fallback: match by resource name
    resource = suffix[0]
    scope = _RESOURCE_SCOPE.get(resource)
    if scope:
        access = "read" if method == "GET" or method == "HEAD" else "write"
        return [(scope, access)]

    return [("unknown", "unknown")]


# ---------------------------------------------------------------------------
# Issue/PR disambiguation
# ---------------------------------------------------------------------------

_REPO_PREFIX = r"(?:/repos/[^/]+/[^/]+|/repositories/\d+)"
_PULLS_RE = re.compile(_REPO_PREFIX + r"/pulls/(\d+)")
_ISSUES_RE = re.compile(_REPO_PREFIX + r"/issues/(\d+)")


def _find_pr_numbers(connections: list[dict]) -> set[str]:
    """Find issue numbers that are confirmed PRs (seen in /pulls/ URLs)."""
    pr_numbers: set[str] = set()
    for conn in connections:
        url = conn.get("url", "")
        m = _PULLS_RE.search(url)
        if m:
            pr_numbers.add(m.group(1))
    return pr_numbers


def _find_ambiguous_numbers(connections: list[dict]) -> set[str]:
    """Find issue numbers from ambiguous /issues/ endpoints."""
    numbers: set[str] = set()
    for conn in connections:
        url = conn.get("url", "")
        m = _ISSUES_RE.search(url)
        if m:
            numbers.add(m.group(1))
    return numbers


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_permissions(connections: list[dict]) -> dict:
    """Analyze connection log for GitHub API permission requirements.

    Args:
        connections: List of connection dicts from JSONL log.

    Returns:
        dict with:
            permissions: dict[scope, access_level] (merged, highest needed)
            details: list of (method, path, scope, access) for each mapped request
            unknown: list of (method, path) that couldn't be mapped
            notes: list of human-readable notes
    """
    permissions: dict[str, str] = {}
    details: list[tuple[str, str, str, str]] = []
    unknown: list[tuple[str, str]] = []
    notes: list[str] = []

    # Filter for github_token-tagged connections only
    token_conns = [c for c in connections if c.get("github_token")]
    if not token_conns:
        return {"permissions": {}, "details": [], "unknown": [], "notes": []}

    # Collect ambiguous issue numbers and confirmed PR numbers for disambiguation
    pr_numbers = _find_pr_numbers(token_conns)
    ambiguous_numbers = _find_ambiguous_numbers(token_conns)

    # Numbers that are ambiguous (in /issues/ but not confirmed as PR)
    unresolved = ambiguous_numbers - pr_numbers

    for conn in token_conns:
        url = conn.get("url", "")
        method = conn.get("method", "GET")

        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path

        # OIDC token request
        if host.endswith(".actions.githubusercontent.com"):
            _merge_permission(permissions, "id-token", "write")
            details.append((method, path, "id-token", "write"))
            continue

        # Release asset upload / download
        if host == "uploads.github.com":
            access = "read" if method in ("GET", "HEAD") else "write"
            _merge_permission(permissions, "contents", access)
            details.append((method, path, "contents", access))
            continue

        # Standard API
        if host != "api.github.com":
            continue

        matches = match_permission(method, path)

        for scope, access in matches:
            if scope == "unknown":
                unknown.append((method, path))
                continue

            if "/" in scope:
                # Ambiguous: "issues/pull-requests"
                # Try to disambiguate using PR numbers from the log
                m = _ISSUES_RE.search(path)
                number = m.group(1) if m else None

                if number and number in pr_numbers:
                    _merge_permission(permissions, "pull-requests", access)
                    details.append((method, path, "pull-requests", access))
                elif number and number in unresolved:
                    # Can't tell — report both conservatively
                    _merge_permission(permissions, "issues", access)
                    _merge_permission(permissions, "pull-requests", access)
                    details.append((method, path, "issues+pull-requests", access))
                else:
                    # No number in path (e.g., /issues/comments/{id})
                    _merge_permission(permissions, "issues", access)
                    _merge_permission(permissions, "pull-requests", access)
                    details.append((method, path, "issues+pull-requests", access))
            else:
                _merge_permission(permissions, scope, access)
                details.append((method, path, scope, access))

    if unresolved:
        nums = ", ".join(sorted(unresolved, key=int))
        notes.append(
            f"Issue numbers {nums} could be issues or PRs; "
            f"reporting both scopes conservatively"
        )

    # Deduplicate unknowns
    unknown = sorted(set(unknown))

    return {
        "permissions": permissions,
        "details": details,
        "unknown": unknown,
        "notes": notes,
    }


def _merge_permission(perms: dict[str, str], scope: str, access: str) -> None:
    """Merge a permission, keeping the highest access level (write > read)."""
    if scope not in perms or access == "write":
        perms[scope] = access


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_permissions_yaml(result: dict) -> str:
    """Format permissions analysis as YAML output."""
    perms = result["permissions"]
    if not perms:
        return "# No GitHub API permissions detected."

    lines = ["permissions:"]
    for scope in sorted(perms):
        lines.append(f"  {scope}: {perms[scope]}")

    notes = result.get("notes", [])
    if notes:
        lines.append("")
        for note in notes:
            lines.append(f"# {note}")

    return "\n".join(lines) + "\n"
