"""Socket.dev API client for package security checks."""

from __future__ import annotations

import json
import logging
import urllib.request
from dataclasses import dataclass, field

logger = logging.getLogger("egress_proxy")

_API_BASE = "https://firewall-api.socket.dev/purl/"
_TIMEOUT = 2  # seconds
_USER_AGENT = "egress-filter/1.0"


@dataclass(frozen=True, slots=True)
class SecurityCheckResult:
    """Result of a Socket.dev security check."""

    blocked: bool
    reasons: list[str] = field(default_factory=list)


class SocketDevClient:
    """Checks packages against Socket.dev's free API.

    Fail-open: any error returns None (logged as warning).
    Results are cached in-memory for the duration of the CI run.
    """

    def __init__(self) -> None:
        self._cache: dict[str, SecurityCheckResult | None] = {}

    def check(self, purl: str) -> SecurityCheckResult | None:
        """Check a PURL against Socket.dev. Returns None on error (fail-open)."""
        if purl in self._cache:
            return self._cache[purl]

        try:
            result = self._fetch(purl)
        except Exception:
            result = None

        self._cache[purl] = result
        return result

    def _fetch(self, purl: str) -> SecurityCheckResult | None:
        url = f"{_API_BASE}{urllib.request.quote(purl, safe='')}"
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                first_line = resp.readline()
        except urllib.error.HTTPError as e:
            if e.code == 429:
                logger.warning("Socket.dev rate-limited (429)")
            else:
                logger.warning(f"Socket.dev HTTP {e.code} for {purl}")
            return None
        except Exception as e:
            logger.warning(f"Socket.dev request failed for {purl}: {e}")
            return None

        try:
            data = json.loads(first_line)
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Socket.dev invalid JSON for {purl}: {e}")
            return None

        blocked = False
        reasons: list[str] = []

        for alert in data.get("alerts", []):
            severity = alert.get("severity", "")
            if severity in ("critical", "high"):
                blocked = True
                alert_type = alert.get("type", "unknown")
                reasons.append(f"{severity}:{alert_type}")

        return SecurityCheckResult(blocked=blocked, reasons=reasons)
