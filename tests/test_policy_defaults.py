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
        # Should have rules for: local DNS resolver, azure wireserver
        assert len(matcher.rules) >= 2

    def test_docker_preset_parses(self):
        """Docker preset should parse without errors."""
        matcher = PolicyMatcher(DOCKER_PRESET)
        # Should have rules for: registry-1, auth, *.docker.io, cloudflare
        assert len(matcher.rules) >= 4


class TestAzureWireserverRules:
    """Test Azure wireserver rules for WALinuxAgent."""

    def test_allows_azure_agent_to_wireserver_port_80(self):
        """Should allow Azure Linux Agent to access wireserver on port 80."""
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

    def test_allows_azure_agent_to_wireserver_port_32526(self):
        """Should allow Azure Linux Agent to access wireserver on port 32526."""
        matcher = PolicyMatcher(GITHUB_ACTIONS_DEFAULTS)
        event = ConnectionEvent(
            type="http",
            dst_ip="168.63.129.16",
            dst_port=32526,
            url="http://168.63.129.16:32526/vmSettings",
            method="GET",
            exe="/usr/bin/python3.12",
            cgroup="/azure.slice/walinuxagent.service",
        )
        allowed, _ = matcher.match(event)
        assert allowed

    def test_allows_azure_agent_put_status(self):
        """Should allow Azure Linux Agent to PUT status."""
        matcher = PolicyMatcher(GITHUB_ACTIONS_DEFAULTS)
        event = ConnectionEvent(
            type="http",
            dst_ip="168.63.129.16",
            dst_port=32526,
            url="http://168.63.129.16:32526/status",
            method="PUT",
            exe="/usr/bin/python3.12",
            cgroup="/azure.slice/walinuxagent.service",
        )
        allowed, _ = matcher.match(event)
        assert allowed

    def test_blocks_non_azure_cgroup_to_wireserver(self):
        """Should block non-Azure cgroup processes from wireserver."""
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
        """User rules should work alongside defaults (inheriting cgroup constraint)."""
        combined = GITHUB_ACTIONS_DEFAULTS + "\n# User rules\nexample.com\n"
        matcher = PolicyMatcher(combined)

        # User rule works when cgroup matches (inherited from defaults header)
        http_event = ConnectionEvent(
            type="http",
            dst_ip="93.184.216.34",
            dst_port=443,
            url="https://example.com/",
            method="GET",
            exe="/usr/bin/curl",
            cgroup="/system.slice/hosted-compute-agent.service",
        )
        allowed, _ = matcher.match(http_event)
        assert allowed

        # Blocked when cgroup doesn't match
        http_event_other_cgroup = ConnectionEvent(
            type="http",
            dst_ip="93.184.216.34",
            dst_port=443,
            url="https://example.com/",
            method="GET",
            exe="/usr/bin/curl",
            cgroup="/user.slice/user-1000.slice",
        )
        allowed, _ = matcher.match(http_event_other_cgroup)
        assert not allowed

    def test_defaults_plus_docker(self):
        """Defaults + Docker preset should allow both."""
        combined = GITHUB_ACTIONS_DEFAULTS + "\n" + DOCKER_PRESET
        matcher = PolicyMatcher(combined)

        # Azure wireserver should work
        azure_event = ConnectionEvent(
            type="http",
            dst_ip="168.63.129.16",
            dst_port=80,
            url="http://168.63.129.16/machine/?comp=goalstate",
            method="GET",
            exe="/usr/bin/python3.12",
            cgroup="/azure.slice/walinuxagent.service",
        )
        allowed, _ = matcher.match(azure_event)
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
