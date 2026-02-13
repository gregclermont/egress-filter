"""Tests for default policy rules."""

import pytest

from proxy.policy.defaults import (
    DEFAULT_POLICY,
    get_defaults,
    get_preset,
)
from proxy.policy.matcher import ConnectionEvent, PolicyMatcher


class TestDefaultsModule:
    """Test the defaults module API."""

    def test_get_defaults_returns_default_policy(self):
        """get_defaults() should return the default policy."""
        assert get_defaults() == DEFAULT_POLICY

    def test_get_preset_defaults(self):
        """get_preset('defaults') should return the default policy."""
        assert get_preset("defaults") == DEFAULT_POLICY

    def test_get_preset_unknown(self):
        """get_preset() should return None for unknown presets."""
        assert get_preset("unknown") is None


class TestDefaultsParsing:
    """Test that default rules parse correctly."""

    def test_default_policy_parses(self):
        """Default policy should parse without errors."""
        matcher = PolicyMatcher(DEFAULT_POLICY)
        # Should have rules for: local DNS resolver, azure wireserver, results-receiver
        assert len(matcher.rules) >= 3


class TestAzureWireserverRules:
    """Test Azure wireserver rules for WALinuxAgent."""

    def test_allows_azure_agent_to_wireserver_port_80(self):
        """Should allow Azure Linux Agent to access wireserver on port 80."""
        matcher = PolicyMatcher(DEFAULT_POLICY)
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
        matcher = PolicyMatcher(DEFAULT_POLICY)
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
        matcher = PolicyMatcher(DEFAULT_POLICY)
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
        matcher = PolicyMatcher(DEFAULT_POLICY)
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


class TestAzureImdsRules:
    """Test Azure IMDS rules for WALinuxAgent."""

    def test_allows_azure_agent_to_imds(self):
        """Should allow Azure Linux Agent to access IMDS."""
        matcher = PolicyMatcher(DEFAULT_POLICY)
        event = ConnectionEvent(
            type="http",
            dst_ip="169.254.169.254",
            dst_port=80,
            url="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            method="GET",
            exe="/usr/bin/python3.12",
            cgroup="/azure.slice/walinuxagent.service",
        )
        allowed, _ = matcher.match(event)
        assert allowed

    def test_blocks_non_azure_cgroup_to_imds(self):
        """Should block non-Azure cgroup processes from IMDS."""
        matcher = PolicyMatcher(DEFAULT_POLICY)
        event = ConnectionEvent(
            type="http",
            dst_ip="169.254.169.254",
            dst_port=80,
            url="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            method="GET",
            exe="/usr/bin/curl",
            cgroup="/system.slice/hosted-compute-agent.service",
        )
        allowed, _ = matcher.match(event)
        assert not allowed


class TestResultsReceiverRules:
    """Test GitHub Actions results receiver rules."""

    def test_allows_runner_worker_to_results_receiver(self):
        """Should allow Runner.Worker to access results-receiver."""
        matcher = PolicyMatcher(DEFAULT_POLICY)
        event = ConnectionEvent(
            type="https",
            dst_ip="140.82.112.10",
            dst_port=443,
            host="results-receiver.actions.githubusercontent.com",
            exe="/home/runner/actions-runner/cached/bin/Runner.Worker",
        )
        allowed, _ = matcher.match(event)
        assert allowed

    def test_allows_action_node_to_results_receiver(self):
        """Should allow action node processes to access results-receiver."""
        matcher = PolicyMatcher(DEFAULT_POLICY)
        event = ConnectionEvent(
            type="https",
            dst_ip="140.82.112.10",
            dst_port=443,
            host="results-receiver.actions.githubusercontent.com",
            exe="/home/runner/actions-runner/cached/externals/node20/bin/node",
        )
        allowed, _ = matcher.match(event)
        assert allowed


class TestCombinedDefaults:
    """Test combining defaults with user rules."""

    def test_user_rules_extend_defaults(self):
        """User rules should work alongside defaults."""
        combined = DEFAULT_POLICY + "\n# User rules\nexample.com\n"
        matcher = PolicyMatcher(combined)

        # User rule works
        https_event = ConnectionEvent(
            type="https",
            dst_ip="93.184.216.34",
            dst_port=443,
            host="example.com",
            exe="/usr/bin/curl",
        )
        allowed, _ = matcher.match(https_event)
        assert allowed
