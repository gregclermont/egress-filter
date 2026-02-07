"""Tests for proxy.permissions — GitHub API permission analysis."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.permissions import (
    analyze_permissions,
    format_permissions_yaml,
    match_permission,
)


# ---------------------------------------------------------------------------
# match_permission
# ---------------------------------------------------------------------------

class TestMatchPermission:
    """Tests for match_permission(method, path)."""

    # -- Explicit map: contents --

    def test_contents_read_branches(self):
        result = match_permission("GET", "/repos/owner/repo/branches")
        assert result == [("contents", "read")]

    def test_contents_read_codeowners(self):
        result = match_permission("GET", "/repos/o/r/codeowners/errors")
        assert result == [("contents", "read")]

    def test_contents_write_merge_pr(self):
        result = match_permission("PUT", "/repos/o/r/pulls/42/merge")
        assert result == [("contents", "write")]

    def test_contents_write_dispatches(self):
        result = match_permission("POST", "/repos/o/r/dispatches")
        assert result == [("contents", "write")]

    def test_contents_write_comment_patch(self):
        result = match_permission("PATCH", "/repos/o/r/comments/123")
        assert result == [("contents", "write")]

    # -- Explicit map: issues --

    def test_issues_write_create(self):
        result = match_permission("POST", "/repos/o/r/issues")
        assert result == [("issues", "write")]

    def test_issues_read_labels(self):
        result = match_permission("GET", "/repos/o/r/labels")
        assert result == [("issues", "read")]

    def test_issues_write_labels(self):
        result = match_permission("POST", "/repos/o/r/labels")
        assert result == [("issues", "write")]

    def test_issues_read_milestones(self):
        result = match_permission("GET", "/repos/o/r/milestones")
        assert result == [("issues", "read")]

    def test_issues_write_milestone_patch(self):
        result = match_permission("PATCH", "/repos/o/r/milestones/1")
        assert result == [("issues", "write")]

    # -- Explicit map: issues/pull-requests (ambiguous) --

    def test_ambiguous_issue_comments_read(self):
        result = match_permission("GET", "/repos/o/r/issues/1/comments")
        assert result == [("issues/pull-requests", "read")]

    def test_ambiguous_issue_comments_write(self):
        result = match_permission("POST", "/repos/o/r/issues/1/comments")
        assert result == [("issues/pull-requests", "write")]

    def test_ambiguous_issue_get(self):
        result = match_permission("GET", "/repos/o/r/issues/42")
        assert result == [("issues/pull-requests", "read")]

    def test_ambiguous_issue_patch(self):
        result = match_permission("PATCH", "/repos/o/r/issues/42")
        assert result == [("issues/pull-requests", "write")]

    def test_ambiguous_issue_labels(self):
        result = match_permission("POST", "/repos/o/r/issues/42/labels")
        assert result == [("issues/pull-requests", "write")]

    def test_ambiguous_issue_reactions(self):
        result = match_permission("POST", "/repos/o/r/issues/42/reactions")
        assert result == [("issues/pull-requests", "write")]

    # -- Explicit map: issues,pull-requests (both) --

    def test_both_issues_list(self):
        result = match_permission("GET", "/repos/o/r/issues")
        assert sorted(result) == [("issues", "read"), ("pull-requests", "read")]

    def test_both_assignees(self):
        result = match_permission("GET", "/repos/o/r/assignees")
        assert sorted(result) == [("issues", "read"), ("pull-requests", "read")]

    def test_both_issue_comments_list(self):
        result = match_permission("GET", "/repos/o/r/issues/comments")
        assert sorted(result) == [("issues", "read"), ("pull-requests", "read")]

    # -- /repositories/{id}/ prefix variant --

    def test_repositories_prefix_branches(self):
        result = match_permission("GET", "/repositories/12345/branches")
        assert result == [("contents", "read")]

    def test_repositories_prefix_issues(self):
        result = match_permission("POST", "/repositories/12345/issues")
        assert result == [("issues", "write")]

    # -- Pattern-based fallback --

    def test_pattern_actions_read(self):
        result = match_permission("GET", "/repos/o/r/actions/runs")
        assert result == [("actions", "read")]

    def test_pattern_actions_write(self):
        result = match_permission("POST", "/repos/o/r/actions/workflows/1/dispatches")
        assert result == [("actions", "write")]

    def test_pattern_checks_write(self):
        result = match_permission("POST", "/repos/o/r/check-runs")
        assert result == [("checks", "write")]

    def test_pattern_check_suites(self):
        result = match_permission("GET", "/repos/o/r/check-suites/123")
        assert result == [("checks", "read")]

    def test_pattern_pulls_read(self):
        result = match_permission("GET", "/repos/o/r/pulls/1")
        assert result == [("pull-requests", "read")]

    def test_pattern_pulls_write(self):
        result = match_permission("POST", "/repos/o/r/pulls")
        assert result == [("pull-requests", "write")]

    def test_pattern_deployments(self):
        result = match_permission("POST", "/repos/o/r/deployments")
        assert result == [("deployments", "write")]

    def test_pattern_statuses(self):
        result = match_permission("POST", "/repos/o/r/statuses/abc123")
        assert result == [("statuses", "write")]

    def test_pattern_pages(self):
        result = match_permission("GET", "/repos/o/r/pages")
        assert result == [("pages", "read")]

    def test_pattern_code_scanning(self):
        result = match_permission("GET", "/repos/o/r/code-scanning/alerts")
        assert result == [("security-events", "read")]

    def test_pattern_releases_read(self):
        result = match_permission("GET", "/repos/o/r/releases")
        assert result == [("contents", "read")]

    def test_pattern_releases_write(self):
        result = match_permission("POST", "/repos/o/r/releases")
        assert result == [("contents", "write")]

    def test_pattern_contents_read(self):
        result = match_permission("GET", "/repos/o/r/contents/README.md")
        assert result == [("contents", "read")]

    def test_pattern_git_read(self):
        result = match_permission("GET", "/repos/o/r/git/refs")
        assert result == [("contents", "read")]

    def test_pattern_commits(self):
        result = match_permission("GET", "/repos/o/r/commits/abc123")
        assert result == [("contents", "read")]

    def test_pattern_packages(self):
        result = match_permission("DELETE", "/repos/o/r/packages/npm/pkg/versions/1")
        assert result == [("packages", "write")]

    # -- Edge cases --

    # -- HEAD method --

    def test_head_treated_as_get_explicit(self):
        """HEAD matches explicit GET entries (same permission)."""
        result = match_permission("HEAD", "/repos/o/r/branches")
        assert result == [("contents", "read")]

    def test_head_treated_as_get_pattern(self):
        """HEAD matches pattern-based fallback as read."""
        result = match_permission("HEAD", "/repos/o/r/actions/runs")
        assert result == [("actions", "read")]

    # -- Edge cases --

    def test_unknown_endpoint(self):
        result = match_permission("GET", "/some/random/path")
        assert result == [("unknown", "unknown")]

    def test_repo_root_no_permission(self):
        """GET /repos/{owner}/{repo} itself — no specific permission needed."""
        result = match_permission("GET", "/repos/o/r")
        assert result == []

    def test_unknown_resource(self):
        result = match_permission("GET", "/repos/o/r/nonexistent-resource")
        assert result == [("unknown", "unknown")]


# ---------------------------------------------------------------------------
# analyze_permissions
# ---------------------------------------------------------------------------

def _conn(url, method="GET", github_token=True, **extra):
    """Helper: create a connection dict."""
    c = {
        "type": "https",
        "url": url,
        "method": method,
        "dst_port": 443,
    }
    if github_token:
        c["github_token"] = True
    c.update(extra)
    return c


class TestAnalyzePermissions:
    """Tests for analyze_permissions(connections)."""

    def test_read_only(self):
        conns = [_conn("https://api.github.com/repos/o/r/branches")]
        result = analyze_permissions(conns)
        assert result["permissions"] == {"contents": "read"}

    def test_write_upgrades_read(self):
        conns = [
            _conn("https://api.github.com/repos/o/r/branches"),
            _conn("https://api.github.com/repos/o/r/dispatches", method="POST"),
        ]
        result = analyze_permissions(conns)
        assert result["permissions"]["contents"] == "write"

    def test_multiple_scopes(self):
        conns = [
            _conn("https://api.github.com/repos/o/r/branches"),
            _conn("https://api.github.com/repos/o/r/issues", method="POST"),
        ]
        result = analyze_permissions(conns)
        assert result["permissions"] == {"contents": "read", "issues": "write"}

    def test_filters_github_token_only(self):
        conns = [
            _conn("https://api.github.com/repos/o/r/branches", github_token=True),
            _conn("https://api.github.com/repos/o/r/deployments", method="POST",
                  github_token=False),
        ]
        result = analyze_permissions(conns)
        assert result["permissions"] == {"contents": "read"}

    def test_non_api_connections_ignored(self):
        conns = [
            _conn("https://example.com/api/data", github_token=True),
        ]
        result = analyze_permissions(conns)
        assert result["permissions"] == {}

    def test_oidc_request(self):
        conns = [
            _conn("https://vstoken.actions.githubusercontent.com/_apis/pipelines/1/runs/1?api-version=7.1",
                  github_token=True),
        ]
        result = analyze_permissions(conns)
        assert result["permissions"] == {"id-token": "write"}

    def test_uploads_github_com(self):
        conns = [
            _conn("https://uploads.github.com/repos/o/r/releases/1/assets?name=f.zip",
                  method="POST", github_token=True),
        ]
        result = analyze_permissions(conns)
        assert result["permissions"] == {"contents": "write"}

    def test_pr_disambiguation_by_pulls_url(self):
        """Issue number seen in /pulls/ URL -> classified as PR."""
        conns = [
            # Explicit /pulls/42 call confirms it's a PR
            _conn("https://api.github.com/repos/o/r/pulls/42"),
            # Ambiguous /issues/42/comments call
            _conn("https://api.github.com/repos/o/r/issues/42/comments"),
        ]
        result = analyze_permissions(conns)
        # Should resolve to pull-requests, not issues
        assert "pull-requests" in result["permissions"]

    def test_pr_disambiguation_conservative_fallback(self):
        """Ambiguous issue number NOT in /pulls/ -> both scopes."""
        conns = [
            _conn("https://api.github.com/repos/o/r/issues/42/comments"),
        ]
        result = analyze_permissions(conns)
        assert "issues" in result["permissions"]
        assert "pull-requests" in result["permissions"]
        assert len(result["notes"]) > 0
        assert "42" in result["notes"][0]
        assert "/repos/o/r" in result["notes"][0]

    def test_empty_log(self):
        result = analyze_permissions([])
        assert result["permissions"] == {}

    def test_unknown_endpoints_reported(self):
        conns = [
            _conn("https://api.github.com/repos/o/r/some-weird-endpoint"),
        ]
        result = analyze_permissions(conns)
        assert len(result["unknown"]) == 1

    def test_details_populated(self):
        conns = [_conn("https://api.github.com/repos/o/r/branches")]
        result = analyze_permissions(conns)
        assert len(result["details"]) == 1
        assert result["details"][0][2] == "contents"

    def test_repositories_prefix_disambiguation(self):
        """/repositories/{id}/pulls/{num} confirms PR for disambiguation."""
        conns = [
            _conn("https://api.github.com/repositories/12345/pulls/7"),
            _conn("https://api.github.com/repositories/12345/issues/7/comments"),
        ]
        result = analyze_permissions(conns)
        assert "pull-requests" in result["permissions"]
        # Should NOT have issues since #7 was confirmed as PR
        assert "issues" not in result["permissions"]

    def test_repositories_prefix_ambiguous_fallback(self):
        """/repositories/{id}/issues/{num} without /pulls/ -> both scopes."""
        conns = [
            _conn("https://api.github.com/repositories/12345/issues/7/comments"),
        ]
        result = analyze_permissions(conns)
        assert "issues" in result["permissions"]
        assert "pull-requests" in result["permissions"]

    def test_cross_repo_disambiguation_independent(self):
        """PR #42 in repo a/x should not affect issue #42 in repo b/y."""
        conns = [
            _conn("https://api.github.com/repos/a/x/pulls/42"),
            _conn("https://api.github.com/repos/b/y/issues/42/comments"),
        ]
        result = analyze_permissions(conns)
        # #42 in b/y is unresolved — both scopes should be reported
        assert "issues" in result["permissions"]
        assert "pull-requests" in result["permissions"]

    def test_cross_repo_disambiguation_same_repo(self):
        """PR #42 confirmed in same repo still disambiguates correctly."""
        conns = [
            _conn("https://api.github.com/repos/o/r/pulls/42"),
            _conn("https://api.github.com/repos/o/r/issues/42/comments"),
        ]
        result = analyze_permissions(conns)
        assert "pull-requests" in result["permissions"]
        assert "issues" not in result["permissions"]


    def test_uploads_github_com_get_is_read(self):
        """GET to uploads.github.com -> contents: read, not write."""
        conns = [
            _conn("https://uploads.github.com/repos/o/r/releases/1/assets",
                  method="GET", github_token=True),
        ]
        result = analyze_permissions(conns)
        assert result["permissions"] == {"contents": "read"}


# ---------------------------------------------------------------------------
# format_permissions_yaml
# ---------------------------------------------------------------------------

class TestFormatPermissionsYaml:
    """Tests for format_permissions_yaml(result)."""

    def test_single_scope(self):
        result = {"permissions": {"contents": "read"}, "notes": [], "unknown": []}
        output = format_permissions_yaml(result)
        assert "permissions:" in output
        assert "  contents: read" in output

    def test_multiple_scopes_sorted(self):
        result = {
            "permissions": {"issues": "write", "contents": "read", "actions": "read"},
            "notes": [],
            "unknown": [],
        }
        output = format_permissions_yaml(result)
        lines = output.strip().split("\n")
        # Should be alphabetical after "permissions:"
        assert lines[1] == "  actions: read"
        assert lines[2] == "  contents: read"
        assert lines[3] == "  issues: write"

    def test_empty_permissions(self):
        result = {"permissions": {}, "notes": [], "unknown": []}
        output = format_permissions_yaml(result)
        assert "No GitHub API permissions detected" in output

    def test_with_notes(self):
        result = {
            "permissions": {"issues": "write"},
            "notes": ["Issue #42 could be issue or PR"],
            "unknown": [],
        }
        output = format_permissions_yaml(result)
        assert "# Issue #42 could be issue or PR" in output
