"""
NetSpecter Enrichment Cache

In-memory cache with TTL for threat intelligence results.
Prevents duplicate API calls and respects rate limits.
"""

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import structlog

from backend.enrichment.models import EnrichmentResult, ThreatLevel

logger = structlog.get_logger(__name__)


@dataclass
class CacheEntry:
    """A cached enrichment result with expiration."""
    
    result: EnrichmentResult
    created_at: float  # Unix timestamp
    expires_at: float  # Unix timestamp
    
    @property
    def is_expired(self) -> bool:
        """Check if this entry has expired."""
        return time.time() > self.expires_at
    
    @property
    def ttl_remaining(self) -> float:
        """Get remaining TTL in seconds."""
        return max(0, self.expires_at - time.time())


class EnrichmentCache:
    """
    Thread-safe in-memory cache for enrichment results.
    
    Features:
    - Different TTLs based on threat level
    - Automatic expiration cleanup
    - Batch lookup support
    - Statistics tracking
    """
    
    # TTL settings (in seconds)
    TTL_MALICIOUS = 6 * 60 * 60  # 6 hours - re-check sooner
    TTL_SUSPICIOUS = 12 * 60 * 60  # 12 hours
    TTL_CLEAN = 24 * 60 * 60  # 24 hours - known good can be cached longer
    TTL_UNKNOWN = 4 * 60 * 60  # 4 hours - retry sooner if we got no data
    
    def __init__(self, max_size: int = 10000):
        """
        Initialize the cache.
        
        Args:
            max_size: Maximum number of entries before cleanup
        """
        self._cache: dict[str, CacheEntry] = {}
        self._lock = threading.RLock()
        self.max_size = max_size
        
        # Statistics
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "expirations": 0,
        }
    
    def _make_key(self, indicator: str, indicator_type: str) -> str:
        """Generate cache key."""
        return f"{indicator_type}:{indicator.lower()}"
    
    def get(self, indicator: str, indicator_type: str) -> EnrichmentResult | None:
        """
        Get a cached result if available and not expired.
        
        Args:
            indicator: The IP or domain
            indicator_type: "ip" or "domain"
        
        Returns:
            Cached EnrichmentResult or None if not found/expired
        """
        key = self._make_key(indicator, indicator_type)
        
        with self._lock:
            entry = self._cache.get(key)
            
            if entry is None:
                self._stats["misses"] += 1
                return None
            
            if entry.is_expired:
                del self._cache[key]
                self._stats["expirations"] += 1
                self._stats["misses"] += 1
                return None
            
            self._stats["hits"] += 1
            
            # Mark result as cached
            result = entry.result
            result.cached = True
            
            return result
    
    def get_many(
        self, 
        indicators: list[tuple[str, str]]
    ) -> tuple[list[EnrichmentResult], list[tuple[str, str]]]:
        """
        Batch lookup multiple indicators.
        
        Args:
            indicators: List of (indicator, indicator_type) tuples
        
        Returns:
            Tuple of (cached_results, missing_indicators)
        """
        cached = []
        missing = []
        
        for indicator, ind_type in indicators:
            result = self.get(indicator, ind_type)
            if result:
                cached.append(result)
            else:
                missing.append((indicator, ind_type))
        
        return cached, missing
    
    def set(self, result: EnrichmentResult) -> None:
        """
        Cache an enrichment result.
        
        TTL is determined by the threat level.
        
        Args:
            result: The EnrichmentResult to cache
        """
        key = self._make_key(result.indicator, result.indicator_type)
        
        # Determine TTL based on threat level
        ttl = self._get_ttl(result.overall_threat_level)
        
        now = time.time()
        entry = CacheEntry(
            result=result,
            created_at=now,
            expires_at=now + ttl,
        )
        
        with self._lock:
            # Check if cleanup needed
            if len(self._cache) >= self.max_size:
                self._cleanup()
            
            self._cache[key] = entry
        
        logger.debug(
            "enrichment_cached",
            indicator=result.indicator,
            threat_level=result.overall_threat_level.value,
            ttl_hours=ttl / 3600,
        )
    
    def set_many(self, results: list[EnrichmentResult]) -> None:
        """Cache multiple results."""
        for result in results:
            self.set(result)
    
    def _get_ttl(self, threat_level: ThreatLevel) -> float:
        """Get TTL in seconds based on threat level."""
        if threat_level == ThreatLevel.MALICIOUS:
            return self.TTL_MALICIOUS
        elif threat_level == ThreatLevel.SUSPICIOUS:
            return self.TTL_SUSPICIOUS
        elif threat_level == ThreatLevel.CLEAN:
            return self.TTL_CLEAN
        else:
            return self.TTL_UNKNOWN
    
    def _cleanup(self) -> None:
        """Remove expired entries and evict oldest if still over limit."""
        now = time.time()
        
        # First pass: remove expired
        expired_keys = [
            key for key, entry in self._cache.items()
            if entry.is_expired
        ]
        for key in expired_keys:
            del self._cache[key]
            self._stats["expirations"] += 1
        
        # If still over limit, evict oldest entries
        if len(self._cache) >= self.max_size:
            # Sort by creation time, evict oldest 10%
            entries = sorted(
                self._cache.items(),
                key=lambda x: x[1].created_at
            )
            evict_count = max(1, len(entries) // 10)
            
            for key, _ in entries[:evict_count]:
                del self._cache[key]
                self._stats["evictions"] += 1
        
        logger.debug(
            "cache_cleanup",
            expired=len(expired_keys),
            current_size=len(self._cache),
        )
    
    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
        
        logger.info("cache_cleared", entries=count)
    
    @property
    def size(self) -> int:
        """Get current cache size."""
        with self._lock:
            return len(self._cache)
    
    @property
    def stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total = self._stats["hits"] + self._stats["misses"]
            hit_rate = self._stats["hits"] / total if total > 0 else 0
            
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._stats["hits"],
                "misses": self._stats["misses"],
                "hit_rate": round(hit_rate, 3),
                "evictions": self._stats["evictions"],
                "expirations": self._stats["expirations"],
            }
    
    def get_all_cached(self) -> list[EnrichmentResult]:
        """Get all non-expired cached results."""
        with self._lock:
            results = []
            for entry in self._cache.values():
                if not entry.is_expired:
                    entry.result.cached = True
                    results.append(entry.result)
            return results


# Global cache instance
_cache_instance: EnrichmentCache | None = None


def get_enrichment_cache() -> EnrichmentCache:
    """Get or create the global cache instance."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = EnrichmentCache()
    return _cache_instance
