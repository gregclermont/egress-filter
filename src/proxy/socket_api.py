"""
Socket Security API client for package security checks.

Queries firewall-api.socket.dev to get security scores and alerts for packages.
Used for inline blocking of malicious packages in the proxy.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import quote

import aiohttp

logger = logging.getLogger("egress_proxy")

SOCKET_API_URL = "https://firewall-api.socket.dev/purl/"
USER_AGENT = "egress-filter/0.1.0"
REQUEST_TIMEOUT = 5.0  # seconds


class Action(Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass
class SecurityAlert:
    type: str
    action: str  # "error", "warn", "info"
    severity: str  # "critical", "high", "medium", "low"
    category: str


@dataclass
class SecurityResult:
    purl: str
    name: str
    version: str
    score: dict | None = None  # license, maintenance, quality, supplyChain, vulnerability
    alerts: list[SecurityAlert] = field(default_factory=list)
    error: str | None = None

    @property
    def action(self) -> Action:
        """Determine action based on alerts."""
        if self.error:
            return Action.ALLOW  # Fail open

        for alert in self.alerts:
            # Block on error actions or critical/high severity
            if alert.action == "error":
                return Action.BLOCK
            if alert.severity in ("critical", "high"):
                return Action.BLOCK

        # Warn on any remaining alerts
        if self.alerts:
            return Action.WARN

        return Action.ALLOW

    @property
    def block_reasons(self) -> list[str]:
        """Get reasons for blocking."""
        reasons = []
        for alert in self.alerts:
            if alert.action == "error" or alert.severity in ("critical", "high"):
                reasons.append(f"{alert.type} ({alert.severity})")
        return reasons


class SocketClient:
    """Async client for Socket Security API with caching."""

    def __init__(self, cache_ttl: int = 3600):
        self._cache: dict[str, SecurityResult] = {}
        self._cache_ttl = cache_ttl
        self._session: aiohttp.ClientSession | None = None
        self._pending: dict[str, asyncio.Future] = {}

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers={"User-Agent": USER_AGENT},
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def check(self, purl: str) -> SecurityResult:
        """
        Check a package's security status.

        Returns cached result if available, otherwise queries the API.
        Deduplicates concurrent requests for the same PURL.
        """
        # Check cache
        if purl in self._cache:
            return self._cache[purl]

        # Check if request is already in flight
        if purl in self._pending:
            return await self._pending[purl]

        # Create future for deduplication
        future: asyncio.Future[SecurityResult] = asyncio.get_event_loop().create_future()
        self._pending[purl] = future

        try:
            result = await self._fetch(purl)
            self._cache[purl] = result
            future.set_result(result)
            return result
        except Exception as e:
            result = SecurityResult(
                purl=purl,
                name="",
                version="",
                error=str(e),
            )
            future.set_result(result)
            return result
        finally:
            self._pending.pop(purl, None)

    async def _fetch(self, purl: str) -> SecurityResult:
        """Fetch security info from Socket API."""
        session = await self._get_session()
        url = SOCKET_API_URL + quote(purl, safe="")

        async with session.get(url) as response:
            if response.status == 404:
                # Package not found - allow it
                return SecurityResult(
                    purl=purl,
                    name=purl.split("/")[-1].split("@")[0] if "/" in purl else "",
                    version=purl.split("@")[-1] if "@" in purl else "",
                )

            response.raise_for_status()
            text = await response.text()

        # Parse NDJSON response (may have multiple lines)
        result = None
        for line in text.strip().split("\n"):
            if not line:
                continue
            import json
            data = json.loads(line)

            alerts = [
                SecurityAlert(
                    type=a.get("type", ""),
                    action=a.get("action", ""),
                    severity=a.get("severity", ""),
                    category=a.get("category", ""),
                )
                for a in data.get("alerts", [])
            ]

            result = SecurityResult(
                purl=data.get("id", purl),
                name=data.get("name", ""),
                version=data.get("version", ""),
                score=data.get("score"),
                alerts=alerts,
            )

        return result or SecurityResult(purl=purl, name="", version="")


# Global client instance
_client: SocketClient | None = None


def get_client() -> SocketClient:
    global _client
    if _client is None:
        _client = SocketClient()
    return _client


async def check_package(purl: str) -> SecurityResult:
    """Convenience function to check a package."""
    return await get_client().check(purl)
