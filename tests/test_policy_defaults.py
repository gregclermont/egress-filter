"""Tests for default policy rules."""

import pytest

from proxy.policy.defaults import (
    DOCKER_PRESET,
    GITHUB_ACTIONS_DEFAULTS,
    get_defaults,
    get_preset,
)
from proxy.policy.matcher import ConnectionEvent, PolicyMatcher


class TestDefaultsModule:
    """Test the defaults module API."""

    def test_get_defaults_returns_github_actions_defaults(self):
        """get_defaults() should return the GitHub Actions defaults."""
        assert get_defaults() == GITHUB_ACTIONS_DEFAULTS

    def test_get_preset_defaults(self):
        """get_preset('defaults') should return GitHub Actions defaults."""
        assert get_preset("defaults") == GITHUB_ACTIONS_DEFAULTS

    def test_get_preset_docker(self):
        """get_preset('docker') should return Docker preset."""
        assert get_preset("docker") == DOCKER_PRESET

    def test_get_preset_unknown(self):
        """get_preset() should return None for unknown presets."""
        assert get_preset("unknown") is None


class TestDefaultsParsing:
    """Test that default rules parse correctly."""

    def test_github_actions_defaults_parses(self):
        """GitHub Actions defaults should parse without errors."""
        matcher = PolicyMatcher(GITHUB_ACTIONS_DEFAULTS)
        # Should have rules for: local DNS, git-remote, node actions, azure
        assert len(matcher.rules) >= 4

    def test_docker_preset_parses(self):
        """Docker preset should parse without errors."""
        matcher = PolicyMatcher(DOCKER_PRESET)
        # Should have rules for: registry-1, auth, *.docker.io, cloudflare
        assert len(matcher.rules) >= 4


class TestGitRemoteRules:
    """Test GitHub repository access rules for git."""

    def test_allows_git_remote_https_to_github(self):
        """Should allow git-remote-https to access github.com."""
        matcher = PolicyMatcher(GITHUB_ACTIONS_DEFAULTS)
        event = ConnectionEvent(
            type="http",
            dst_ip="140.82.113.4",
            dst_port=443,
            url="https://github.com/owner/repo/info/refs?service=git-upload-pack",
            method="GET",
            exe="/usr/lib/git-core/git-remote-https",
        )
        allowed, _ = matcher.match(event)
        assert allowed

    def test_allows_git_remote_http_to_github(self):
        """Should allow git-remote-http to access github.com."""
        matcher = PolicyMatcher(GITHUB_ACTIONS_DEFAULTS)
        event = ConnectionEvent(
            type="http",
            dst_ip="140.82.113.4",
            dst_port=443,
            url="https://github.com/owner/repo/git-upload-pack",
            method="POST",
            exe="/usr/lib/git-core/git-remote-http",
        )
        allowed, _ = matcher.match(event)
        assert allowed

    def test_allows_git_to_subdomain(self):
        """Should allow git to access *.github.com."""
        matcher = PolicyMatcher(GITHUB_ACTIONS_DEFAULTS)
        event = ConnectionEvent(
            type="http",
            dst_ip="140.82.113.4",
            dst_port=443,
            url="https://api.github.com/repos/owner/repo",
            method="GET",
            exe="/usr/lib/git-core/git-remote-https",
        )
        allowed, _ = matcher.match(event)
        assert allowed

    def test_blocks_non_git_exe_to_github(self):
        """Should block non-git executables from github.com via this rule."""
        matcher = PolicyMatcher(GITHUB_ACTIONS_DEFAULTS)
        event = ConnectionEvent(
            type="http",
            dst_ip="140.82.113.4",
            dst_port=443,
            url="https://github.com/owner/repo",
            method="GET",
            exe="/usr/bin/curl",
        )
        allowed, _ = matcher.match(event)
        # Note: This is blocked because the git-remote rule requires exe match
        # A user would need to add their own rule for curl -> github.com
        assert not allowed

    def test_blocks_git_to_other_hosts(self):
        """Should block git executables from non-github hosts."""
        matcher = PolicyMatcher(GITHUB_ACTIONS_DEFAULTS)
        event = ConnectionEvent(
            type="http",
            dst_ip="10.0.0.1",
            dst_port=443,
            url="https://gitlab.com/owner/repo",
            method="GET",
            exe="/usr/lib/git-core/git-remote-https",
        )
        allowed, _ = matcher.match(event)
        assert not allowed


class TestActionsRunnerRules:
    """Test GitHub Actions runner (node) rules."""

    def test_allows_node_to_actions_githubusercontent(self):
        """Should allow actions-runner node to access *.actions.githubusercontent.com."""
        matcher = PolicyMatcher(GITHUB_ACTIONS_DEFAULTS)
        event = ConnectionEvent(
            type="http",
            dst_ip="185.199.108.154",
            dst_port=443,
            url="https://results-receiver.actions.githubusercontent.com/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact",
            method="POST",
            exe="/home/runner/actions-runner/cached/externals/node20/bin/node",
        )
        allowed, _ = matcher.match(event)
        assert allowed

    def test_allows_node_to_githubusercontent(self):
        """Should allow actions-runner node to access *.githubusercontent.com."""
        matcher = PolicyMatcher(GITHUB_ACTIONS_DEFAULTS)
        event = ConnectionEvent(
            type="http",
            dst_ip="185.199.108.133",
            dst_port=443,
            url="https://raw.githubusercontent.com/owner/repo/main/file.txt",
            method="GET",
            exe="/home/runner/actions-runner/cached/externals/node22/bin/node",
        )
        allowed, _ = matcher.match(event)
        assert allowed

    def test_blocks_other_node_to_githubusercontent(self):
        """Should block other node processes from githubusercontent."""
        matcher = PolicyMatcher(GITHUB_ACTIONS_DEFAULTS)
        event = ConnectionEvent(
            type="http",
            dst_ip="185.199.108.133",
            dst_port=443,
            url="https://raw.githubusercontent.com/owner/repo/main/file.txt",
            method="GET",
            exe="/usr/bin/node",  # Not actions-runner node
        )
        allowed, _ = matcher.match(event)
        assert not allowed


class TestAzureWireserverRules:
    """Test Azure wireserver rules for WALinuxAgent."""

    def test_allows_azure_agent_to_wireserver(self):
        """Should allow Azure Linux Agent to access wireserver."""
        matcher = PolicyMatcher(GITHUB_ACTIONS_DEFAULTS)
        event = ConnectionEvent(
            type="http",
            dst_ip="168.63.129.16",
            dst_port=80,
            url="http://168.63.129.16/machine/?comp=goalstate",
            method="GET",
            exe="/usr/bin/python3.12",
            cgroup="/azure.slice/walinuxagent.service",
        )
        allowed, _ = matcher.match(event)
        assert allowed

    def test_blocks_non_azure_agent_to_wireserver(self):
        """Should block non-Azure processes from wireserver."""
        matcher = PolicyMatcher(GITHUB_ACTIONS_DEFAULTS)
        event = ConnectionEvent(
            type="http",
            dst_ip="168.63.129.16",
            dst_port=80,
            url="http://168.63.129.16/machine/?comp=goalstate",
            method="GET",
            exe="/usr/bin/curl",
            cgroup="/system.slice/hosted-compute-agent.service",
        )
        allowed, _ = matcher.match(event)
        assert not allowed


class TestDockerPreset:
    """Test Docker registry preset rules."""

    def test_allows_dockerd_to_registry(self):
        """Should allow dockerd to access Docker registry."""
        matcher = PolicyMatcher(DOCKER_PRESET)
        event = ConnectionEvent(
            type="http",
            dst_ip="52.72.142.170",
            dst_port=443,
            url="https://registry-1.docker.io/v2/",
            method="GET",
            exe="/usr/bin/dockerd",
        )
        allowed, _ = matcher.match(event)
        assert allowed

    def test_allows_dockerd_to_auth(self):
        """Should allow dockerd to access Docker auth."""
        matcher = PolicyMatcher(DOCKER_PRESET)
        event = ConnectionEvent(
            type="http",
            dst_ip="100.48.251.245",
            dst_port=443,
            url="https://auth.docker.io/token?account=user&scope=repository:library/python:pull",
            method="GET",
            exe="/usr/bin/dockerd",
        )
        allowed, _ = matcher.match(event)
        assert allowed

    def test_allows_dockerd_to_cloudflare_cdn(self):
        """Should allow dockerd to access Docker's Cloudflare CDN."""
        matcher = PolicyMatcher(DOCKER_PRESET)
        event = ConnectionEvent(
            type="http",
            dst_ip="104.16.101.215",
            dst_port=443,
            url="https://production.cloudflare.docker.com/registry-v2/docker/registry/v2/blobs/sha256/ab/abcd/data",
            method="GET",
            exe="/usr/bin/dockerd",
        )
        allowed, _ = matcher.match(event)
        assert allowed

    def test_blocks_non_dockerd_to_registry(self):
        """Should block non-dockerd from Docker registry."""
        matcher = PolicyMatcher(DOCKER_PRESET)
        event = ConnectionEvent(
            type="http",
            dst_ip="52.72.142.170",
            dst_port=443,
            url="https://registry-1.docker.io/v2/",
            method="GET",
            exe="/usr/bin/curl",
        )
        allowed, _ = matcher.match(event)
        assert not allowed


class TestCombinedDefaults:
    """Test combining defaults with user rules."""

    def test_user_rules_extend_defaults(self):
        """User rules should work alongside defaults."""
        combined = GITHUB_ACTIONS_DEFAULTS + "\n# User rules\nexample.com\n"
        matcher = PolicyMatcher(combined)

        # User rule should work
        http_event = ConnectionEvent(
            type="http",
            dst_ip="93.184.216.34",
            dst_port=443,
            url="https://example.com/",
            method="GET",
            exe="/usr/bin/curl",
        )
        allowed, _ = matcher.match(http_event)
        assert allowed

    def test_defaults_plus_docker(self):
        """Defaults + Docker preset should allow both."""
        combined = GITHUB_ACTIONS_DEFAULTS + "\n" + DOCKER_PRESET
        matcher = PolicyMatcher(combined)

        # GitHub should work
        git_event = ConnectionEvent(
            type="http",
            dst_ip="140.82.113.4",
            dst_port=443,
            url="https://github.com/owner/repo",
            method="GET",
            exe="/usr/lib/git-core/git-remote-https",
        )
        allowed, _ = matcher.match(git_event)
        assert allowed

        # Docker should work
        docker_event = ConnectionEvent(
            type="http",
            dst_ip="52.72.142.170",
            dst_port=443,
            url="https://registry-1.docker.io/v2/",
            method="GET",
            exe="/usr/bin/dockerd",
        )
        allowed, _ = matcher.match(docker_event)
        assert allowed
