"""Tests for proxy.proc — container ID parsing and Docker image lookup."""

import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.proc import parse_container_id, lookup_container_image, _container_image_cache


# ---------------------------------------------------------------------------
# parse_container_id
# ---------------------------------------------------------------------------

class TestParseContainerId:
    """Tests for extracting Docker container IDs from cgroup paths."""

    def test_cgroup_v2_docker_scope(self):
        """Standard cgroup v2 format on GitHub-hosted Ubuntu 24.04."""
        cid = "a" * 64
        cgroup = f"/system.slice/docker-{cid}.scope"
        assert parse_container_id(cgroup) == cid

    def test_real_hex_id(self):
        """Realistic 64-char hex container ID."""
        cid = "d7b0a6e5f3c2e1d0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f0"
        assert len(cid) == 64
        cgroup = f"/system.slice/docker-{cid}.scope"
        assert parse_container_id(cgroup) == cid

    def test_non_docker_cgroup(self):
        """Non-Docker cgroup path returns None."""
        assert parse_container_id("/system.slice/runner.service") is None

    def test_runner_cgroup(self):
        """Runner cgroup returns None."""
        assert parse_container_id("/system.slice/hosted-compute-agent.service") is None

    def test_short_id(self):
        """Container ID shorter than 64 chars doesn't match."""
        cgroup = "/system.slice/docker-abc123.scope"
        assert parse_container_id(cgroup) is None

    def test_empty_string(self):
        assert parse_container_id("") is None

    def test_uppercase_hex_not_matched(self):
        """Uppercase hex chars don't match (Docker uses lowercase)."""
        cid = "A" * 64
        cgroup = f"/system.slice/docker-{cid}.scope"
        assert parse_container_id(cgroup) is None

    def test_cgroup_v1_docker_path(self):
        """cgroup v1 /docker/ path does NOT match the regex (different format)."""
        assert parse_container_id("/docker/abc123") is None


# ---------------------------------------------------------------------------
# lookup_container_image
# ---------------------------------------------------------------------------

class TestLookupContainerImage:
    """Tests for Docker socket API queries."""

    def setup_method(self):
        """Clear cache before each test."""
        _container_image_cache.clear()

    def test_successful_lookup(self):
        """Successful Docker API response returns image name."""
        cid = "a" * 64
        response_body = json.dumps({"Config": {"Image": "node:18-alpine"}})

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = response_body.encode()

        with patch("proxy.proc._UnixHTTPConnection") as MockConn:
            instance = MockConn.return_value
            instance.getresponse.return_value = mock_resp
            result = lookup_container_image(cid)

        assert result == "node:18-alpine"
        # Verify correct API path
        instance.request.assert_called_once_with("GET", f"/containers/{cid}/json")

    def test_cache_hit(self):
        """Second lookup for same container ID uses cache."""
        cid = "b" * 64
        response_body = json.dumps({"Config": {"Image": "python:3.11"}})

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = response_body.encode()

        with patch("proxy.proc._UnixHTTPConnection") as MockConn:
            instance = MockConn.return_value
            instance.getresponse.return_value = mock_resp

            result1 = lookup_container_image(cid)
            result2 = lookup_container_image(cid)

        assert result1 == "python:3.11"
        assert result2 == "python:3.11"
        # Only one HTTP call — second was cached
        assert instance.request.call_count == 1

    def test_socket_error_returns_none(self):
        """Connection error to Docker socket returns None (fail-open)."""
        cid = "c" * 64

        with patch("proxy.proc._UnixHTTPConnection") as MockConn:
            MockConn.return_value.request.side_effect = ConnectionRefusedError()
            result = lookup_container_image(cid)

        assert result is None

    def test_failure_cached(self):
        """Failed lookup caches None so we don't retry."""
        cid = "d" * 64

        with patch("proxy.proc._UnixHTTPConnection") as MockConn:
            MockConn.return_value.request.side_effect = ConnectionRefusedError()
            lookup_container_image(cid)

        # Second call should use cache, not make a new connection
        with patch("proxy.proc._UnixHTTPConnection") as MockConn:
            result = lookup_container_image(cid)

        assert result is None
        MockConn.assert_not_called()

    def test_404_returns_none(self):
        """Container not found (404) returns None."""
        cid = "e" * 64

        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.read.return_value = b'{"message": "No such container"}'

        with patch("proxy.proc._UnixHTTPConnection") as MockConn:
            instance = MockConn.return_value
            instance.getresponse.return_value = mock_resp
            result = lookup_container_image(cid)

        assert result is None

    def test_malformed_json_returns_none_and_caches(self):
        """Malformed JSON response returns None and caches the failure."""
        cid = "f" * 64

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"not json"

        with patch("proxy.proc._UnixHTTPConnection") as MockConn:
            instance = MockConn.return_value
            instance.getresponse.return_value = mock_resp
            result = lookup_container_image(cid)

        assert result is None

        # Second call should use cache, not make a new connection
        with patch("proxy.proc._UnixHTTPConnection") as MockConn:
            result = lookup_container_image(cid)

        assert result is None
        MockConn.assert_not_called()
