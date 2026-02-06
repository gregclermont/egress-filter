"""Tests for proxy.socket_dev — Socket.dev API client."""

import json
import sys
import urllib.error
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.socket_dev import SecurityCheckResult, SocketDevClient


def _mock_response(data: dict) -> MagicMock:
    """Create a mock urlopen response returning NDJSON."""
    line = json.dumps(data).encode() + b"\n"
    buf = BytesIO(line)
    mock = MagicMock()
    mock.readline = buf.readline
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    return mock


class TestSocketDevClient:
    def test_clean_package(self):
        """No alerts → not blocked."""
        resp = _mock_response({"alerts": []})
        with patch("proxy.socket_dev.urllib.request.urlopen", return_value=resp):
            client = SocketDevClient()
            result = client.check("pkg:npm/express@4.18.2")

        assert result is not None
        assert result.blocked is False
        assert result.reasons == []

    def test_malicious_package(self):
        """Critical alert → blocked with reason."""
        resp = _mock_response({
            "alerts": [
                {"severity": "critical", "type": "malware"},
            ],
        })
        with patch("proxy.socket_dev.urllib.request.urlopen", return_value=resp):
            client = SocketDevClient()
            result = client.check("pkg:npm/evil-pkg@1.0.0")

        assert result is not None
        assert result.blocked is True
        assert result.reasons == ["critical:malware"]

    def test_high_severity_blocks(self):
        """High severity alert → blocked."""
        resp = _mock_response({
            "alerts": [
                {"severity": "high", "type": "protestware"},
            ],
        })
        with patch("proxy.socket_dev.urllib.request.urlopen", return_value=resp):
            client = SocketDevClient()
            result = client.check("pkg:npm/bad@1.0.0")

        assert result.blocked is True
        assert "high:protestware" in result.reasons

    def test_low_severity_not_blocked(self):
        """Low/medium severity → not blocked."""
        resp = _mock_response({
            "alerts": [
                {"severity": "low", "type": "noTests"},
                {"severity": "medium", "type": "noLicense"},
            ],
        })
        with patch("proxy.socket_dev.urllib.request.urlopen", return_value=resp):
            client = SocketDevClient()
            result = client.check("pkg:npm/meh@1.0.0")

        assert result.blocked is False

    def test_cache_hit(self):
        """Second call for same PURL uses cache (no HTTP call)."""
        resp = _mock_response({"alerts": []})
        with patch("proxy.socket_dev.urllib.request.urlopen", return_value=resp) as mock_urlopen:
            client = SocketDevClient()
            r1 = client.check("pkg:npm/cached@1.0.0")
            r2 = client.check("pkg:npm/cached@1.0.0")

        assert r1 == r2
        assert mock_urlopen.call_count == 1

    def test_fail_open_on_timeout(self):
        """Timeout → returns None (fail-open), no exception raised."""
        with patch("proxy.socket_dev.urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            client = SocketDevClient()
            result = client.check("pkg:npm/timeout@1.0.0")

        assert result is None

    def test_fail_open_on_connection_error(self):
        """Connection error → returns None."""
        with patch("proxy.socket_dev.urllib.request.urlopen", side_effect=ConnectionError()):
            client = SocketDevClient()
            result = client.check("pkg:npm/offline@1.0.0")

        assert result is None

    def test_rate_limit_429(self):
        """429 → returns None, logs rate-limit warning."""
        error = urllib.error.HTTPError(
            url="https://firewall-api.socket.dev/purl",
            code=429,
            msg="Too Many Requests",
            hdrs={},
            fp=BytesIO(b""),
        )
        with patch("proxy.socket_dev.urllib.request.urlopen", side_effect=error), \
             patch("proxy.socket_dev.logger") as mock_logger:
            client = SocketDevClient()
            result = client.check("pkg:npm/limited@1.0.0")

        assert result is None
        mock_logger.warning.assert_called_once()
        assert "429" in mock_logger.warning.call_args[0][0]

    def test_http_500(self):
        """Server error → returns None."""
        error = urllib.error.HTTPError(
            url="https://firewall-api.socket.dev/purl",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=BytesIO(b""),
        )
        with patch("proxy.socket_dev.urllib.request.urlopen", side_effect=error):
            client = SocketDevClient()
            result = client.check("pkg:npm/broken@1.0.0")

        assert result is None

    def test_invalid_json(self):
        """Invalid JSON → returns None."""
        mock = MagicMock()
        mock.readline.return_value = b"not json\n"
        mock.__enter__ = lambda s: s
        mock.__exit__ = MagicMock(return_value=False)
        with patch("proxy.socket_dev.urllib.request.urlopen", return_value=mock):
            client = SocketDevClient()
            result = client.check("pkg:npm/garbled@1.0.0")

        assert result is None

    def test_cache_none_result(self):
        """Failed check (None) is also cached."""
        with patch("proxy.socket_dev.urllib.request.urlopen", side_effect=TimeoutError()) as mock_urlopen:
            client = SocketDevClient()
            r1 = client.check("pkg:npm/fail@1.0.0")
            r2 = client.check("pkg:npm/fail@1.0.0")

        assert r1 is None
        assert r2 is None
        assert mock_urlopen.call_count == 1

    def test_multiple_critical_alerts(self):
        """Multiple critical/high alerts → all collected in reasons."""
        resp = _mock_response({
            "alerts": [
                {"severity": "critical", "type": "malware"},
                {"severity": "high", "type": "installScripts"},
                {"severity": "low", "type": "noTests"},
            ],
        })
        with patch("proxy.socket_dev.urllib.request.urlopen", return_value=resp):
            client = SocketDevClient()
            result = client.check("pkg:npm/multi@1.0.0")

        assert result.blocked is True
        assert result.reasons == ["critical:malware", "high:installScripts"]

    def test_request_url_and_headers(self):
        """Verify correct API endpoint URL and User-Agent header."""
        resp = _mock_response({"alerts": []})
        with patch("proxy.socket_dev.urllib.request.urlopen", return_value=resp) as mock_urlopen:
            client = SocketDevClient()
            client.check("pkg:npm/express@4.18.2")

        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://firewall-api.socket.dev/purl/pkg%3Anpm%2Fexpress%404.18.2"
        assert req.get_header("User-agent") == "egress-filter/1.0"
