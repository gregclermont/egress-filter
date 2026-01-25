"""DNS IP cache for correlating resolved IPs back to hostnames.

When a DNS query resolves a hostname to IPs, we cache the mapping.
Later, when a TCP/UDP connection arrives to one of those IPs,
we can look up the original hostname for policy matching.
"""

import threading
import time
from dataclasses import dataclass


@dataclass
class CacheEntry:
    """A cached DNS resolution entry."""

    hostname: str
    expiry: float  # Unix timestamp

    def is_expired(self, now: float | None = None) -> bool:
        """Check if this entry has expired."""
        if now is None:
            now = time.time()
        return now >= self.expiry


class DNSIPCache:
    """Thread-safe cache mapping IPs to hostnames from DNS responses.

    Used to correlate TCP/UDP connections back to the hostname that
    was resolved to get that IP address. This allows hostname-based
    policy rules to work even for raw TCP connections.

    The cache has a configurable maximum size. When full, entries closest
    to expiry are evicted first (expired entries are always evicted first).

    Example:
        cache = DNSIPCache()

        # When DNS resolves github.com -> 140.82.121.4
        cache.add("140.82.121.4", "github.com", ttl=300)

        # Later, when TCP connects to 140.82.121.4
        hostname = cache.lookup("140.82.121.4")  # Returns "github.com"
    """

    # Maximum TTL to prevent stale entries (1 hour)
    MAX_TTL = 3600

    # Minimum TTL to ensure some caching even for low-TTL records
    MIN_TTL = 60

    # Default maximum cache size (number of IP entries)
    DEFAULT_MAX_SIZE = 10000

    def __init__(
        self,
        max_ttl: int = MAX_TTL,
        min_ttl: int = MIN_TTL,
        max_size: int = DEFAULT_MAX_SIZE,
    ):
        self._cache: dict[str, CacheEntry] = {}
        self._lock = threading.Lock()
        self._max_ttl = max_ttl
        self._min_ttl = min_ttl
        self._max_size = max_size
        self._eviction_count = 0

    def _evict_if_needed(self, space_needed: int = 1) -> None:
        """Evict entries if cache is at or over capacity. Must hold lock."""
        if len(self._cache) + space_needed <= self._max_size:
            return

        now = time.time()

        # First pass: remove expired entries
        expired_ips = [ip for ip, entry in self._cache.items() if entry.is_expired(now)]
        for ip in expired_ips:
            del self._cache[ip]
            self._eviction_count += 1

        # Check if we have enough space now
        if len(self._cache) + space_needed <= self._max_size:
            return

        # Second pass: evict entries closest to expiry
        entries_to_evict = len(self._cache) + space_needed - self._max_size
        if entries_to_evict > 0:
            # Sort by expiry time (soonest first)
            sorted_ips = sorted(
                self._cache.keys(), key=lambda ip: self._cache[ip].expiry
            )
            for ip in sorted_ips[:entries_to_evict]:
                del self._cache[ip]
                self._eviction_count += 1

    def add(self, ip: str, hostname: str, ttl: int) -> None:
        """Add an IP -> hostname mapping with TTL.

        Args:
            ip: The IP address (as string)
            hostname: The hostname that resolved to this IP
            ttl: Time-to-live in seconds from DNS response
        """
        # Clamp TTL to reasonable bounds
        effective_ttl = max(self._min_ttl, min(ttl, self._max_ttl))
        expiry = time.time() + effective_ttl

        with self._lock:
            # If IP already exists, no new space needed
            space_needed = 0 if ip in self._cache else 1
            self._evict_if_needed(space_needed)
            self._cache[ip] = CacheEntry(hostname=hostname.lower(), expiry=expiry)

    def add_many(self, ips: list[str], hostname: str, ttl: int) -> None:
        """Add multiple IPs for the same hostname.

        Args:
            ips: List of IP addresses
            hostname: The hostname that resolved to these IPs
            ttl: Time-to-live in seconds
        """
        effective_ttl = max(self._min_ttl, min(ttl, self._max_ttl))
        expiry = time.time() + effective_ttl
        entry = CacheEntry(hostname=hostname.lower(), expiry=expiry)

        with self._lock:
            # Count how many IPs are new (not already in cache)
            new_ips = [ip for ip in ips if ip not in self._cache]
            self._evict_if_needed(len(new_ips))
            for ip in ips:
                self._cache[ip] = entry

    def lookup(self, ip: str) -> str | None:
        """Look up the hostname for an IP address.

        Args:
            ip: The IP address to look up

        Returns:
            The hostname if found and not expired, None otherwise
        """
        with self._lock:
            entry = self._cache.get(ip)
            if entry is None:
                return None
            if entry.is_expired():
                # Clean up expired entry
                del self._cache[ip]
                return None
            return entry.hostname

    def cleanup_expired(self) -> int:
        """Remove all expired entries from the cache.

        Returns:
            Number of entries removed
        """
        now = time.time()
        removed = 0

        with self._lock:
            expired_ips = [
                ip for ip, entry in self._cache.items() if entry.is_expired(now)
            ]
            for ip in expired_ips:
                del self._cache[ip]
                removed += 1

        return removed

    def clear(self) -> None:
        """Clear all entries from the cache."""
        with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        """Return the number of entries in the cache (including expired)."""
        with self._lock:
            return len(self._cache)

    def stats(self) -> dict:
        """Return cache statistics.

        Returns:
            Dict with 'total', 'valid', 'expired', 'max_size', 'evictions' counts
        """
        now = time.time()
        with self._lock:
            total = len(self._cache)
            expired = sum(1 for e in self._cache.values() if e.is_expired(now))
            return {
                "total": total,
                "valid": total - expired,
                "expired": expired,
                "max_size": self._max_size,
                "evictions": self._eviction_count,
            }
