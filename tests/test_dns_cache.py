"""Unit tests for DNSIPCache.

These tests verify the DNS IP cache functionality that can't be easily
expressed in YAML fixtures (TTL, expiry, thread-safety).

Scenario-based enforcer tests are in tests/fixtures/policy_enforcer.yaml.
"""

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.policy import DNSIPCache


class TestDNSIPCache:
    """Tests for DNS IP correlation cache."""

    def test_add_and_lookup(self):
        """Basic add and lookup."""
        cache = DNSIPCache()
        cache.add("140.82.121.4", "github.com", ttl=300)

        assert cache.lookup("140.82.121.4") == "github.com"
        assert cache.lookup("8.8.8.8") is None

    def test_add_many(self):
        """Add multiple IPs for same hostname."""
        cache = DNSIPCache()
        cache.add_many(
            ["140.82.121.4", "140.82.121.5", "140.82.121.6"],
            "github.com",
            ttl=300,
        )

        assert cache.lookup("140.82.121.4") == "github.com"
        assert cache.lookup("140.82.121.5") == "github.com"
        assert cache.lookup("140.82.121.6") == "github.com"

    def test_hostname_normalized_to_lowercase(self):
        """Hostnames are stored lowercase."""
        cache = DNSIPCache()
        cache.add("140.82.121.4", "GitHub.COM", ttl=300)

        assert cache.lookup("140.82.121.4") == "github.com"

    def test_expiry(self):
        """Entries expire based on TTL."""
        cache = DNSIPCache(min_ttl=1, max_ttl=1)
        cache.add("140.82.121.4", "github.com", ttl=1)

        # Should exist immediately
        assert cache.lookup("140.82.121.4") == "github.com"

        # Wait for expiry
        time.sleep(1.1)

        # Should be gone
        assert cache.lookup("140.82.121.4") is None

    def test_ttl_clamped_to_max(self):
        """TTL is clamped to max_ttl."""
        cache = DNSIPCache(max_ttl=10)
        cache.add("140.82.121.4", "github.com", ttl=9999)

        # Entry should exist
        assert cache.lookup("140.82.121.4") == "github.com"

    def test_ttl_clamped_to_min(self):
        """TTL is clamped to min_ttl."""
        cache = DNSIPCache(min_ttl=60)
        cache.add("140.82.121.4", "github.com", ttl=1)

        # Should still exist after 1 second (min_ttl is 60)
        time.sleep(1.1)
        assert cache.lookup("140.82.121.4") == "github.com"

    def test_cleanup_expired(self):
        """cleanup_expired removes old entries."""
        cache = DNSIPCache(min_ttl=1, max_ttl=1)
        cache.add("140.82.121.4", "github.com", ttl=1)
        cache.add("8.8.8.8", "dns.google", ttl=1)

        assert len(cache) == 2

        time.sleep(1.1)
        removed = cache.cleanup_expired()

        assert removed == 2
        assert len(cache) == 0

    def test_clear(self):
        """clear removes all entries."""
        cache = DNSIPCache()
        cache.add("140.82.121.4", "github.com", ttl=300)
        cache.add("8.8.8.8", "dns.google", ttl=300)

        cache.clear()

        assert len(cache) == 0
        assert cache.lookup("140.82.121.4") is None

    def test_stats(self):
        """stats returns correct counts."""
        cache = DNSIPCache(min_ttl=1, max_ttl=1)
        cache.add("140.82.121.4", "github.com", ttl=300)  # Will be clamped to 1
        cache.add("8.8.8.8", "dns.google", ttl=300)

        stats = cache.stats()
        assert stats["total"] == 2
        assert stats["valid"] == 2
        assert stats["expired"] == 0

        time.sleep(1.1)

        stats = cache.stats()
        assert stats["total"] == 2
        assert stats["valid"] == 0
        assert stats["expired"] == 2

    def test_overwrite_existing(self):
        """Adding same IP overwrites previous entry."""
        cache = DNSIPCache()
        cache.add("140.82.121.4", "github.com", ttl=300)
        cache.add("140.82.121.4", "api.github.com", ttl=300)

        assert cache.lookup("140.82.121.4") == "api.github.com"

    def test_max_size_eviction(self):
        """Cache evicts entries when max_size is exceeded."""
        cache = DNSIPCache(max_size=3)

        # Add 3 entries with different TTLs (60 is min_ttl default)
        cache.add("1.1.1.1", "one.com", ttl=100)
        cache.add("2.2.2.2", "two.com", ttl=200)
        cache.add("3.3.3.3", "three.com", ttl=300)

        assert len(cache) == 3

        # Add a 4th - should evict the one closest to expiry (one.com)
        cache.add("4.4.4.4", "four.com", ttl=400)

        assert len(cache) == 3
        assert cache.lookup("1.1.1.1") is None  # Evicted (shortest TTL)
        assert cache.lookup("2.2.2.2") == "two.com"
        assert cache.lookup("3.3.3.3") == "three.com"
        assert cache.lookup("4.4.4.4") == "four.com"

        stats = cache.stats()
        assert stats["evictions"] == 1
        assert stats["max_size"] == 3

    def test_max_size_eviction_prefers_expired(self):
        """Cache evicts expired entries first before TTL-based eviction."""
        cache = DNSIPCache(max_size=3, min_ttl=1, max_ttl=1)

        # Add entries that will expire quickly
        cache.add("1.1.1.1", "one.com", ttl=1)

        # Wait for expiry
        time.sleep(1.1)

        # Add two more with longer TTL
        cache = DNSIPCache(max_size=3, min_ttl=60)
        cache.add("1.1.1.1", "one.com", ttl=60)  # Will expire first
        time.sleep(0.01)  # Small delay to ensure different expiry times
        cache.add("2.2.2.2", "two.com", ttl=200)
        cache.add("3.3.3.3", "three.com", ttl=300)

        # Add 4th - should evict 1.1.1.1 (closest to expiry)
        cache.add("4.4.4.4", "four.com", ttl=400)

        assert len(cache) == 3
        assert cache.lookup("1.1.1.1") is None

    def test_max_size_add_many(self):
        """add_many respects max_size."""
        cache = DNSIPCache(max_size=5)

        # Add 3 entries
        cache.add("1.1.1.1", "one.com", ttl=100)
        cache.add("2.2.2.2", "two.com", ttl=200)
        cache.add("3.3.3.3", "three.com", ttl=300)

        # Add 3 more via add_many - should evict 1 to stay at max_size=5
        cache.add_many(["4.4.4.4", "5.5.5.5", "6.6.6.6"], "multi.com", ttl=400)

        assert len(cache) == 5
        assert cache.lookup("1.1.1.1") is None  # Evicted

    def test_max_size_no_eviction_for_existing_ip(self):
        """Updating an existing IP doesn't trigger eviction."""
        cache = DNSIPCache(max_size=2)

        cache.add("1.1.1.1", "one.com", ttl=100)
        cache.add("2.2.2.2", "two.com", ttl=200)

        # Update existing IP - should not evict
        cache.add("1.1.1.1", "updated.com", ttl=300)

        assert len(cache) == 2
        assert cache.lookup("1.1.1.1") == "updated.com"
        assert cache.lookup("2.2.2.2") == "two.com"

        stats = cache.stats()
        assert stats["evictions"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
