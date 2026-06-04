"""
Tests for NetSpecter Threat Intelligence Enrichment.
"""

import pytest
from unittest.mock import AsyncMock, patch

from backend.enrichment.filter import IndicatorFilter, IndicatorPriority, FilteredIndicator
from backend.enrichment.cache import EnrichmentCache
from backend.enrichment.models import (
    EnrichmentResult,
    VirusTotalResult,
    AbuseIPDBResult,
    OTXResult,
    ThreatLevel,
)


class TestIndicatorFilter:
    """Tests for indicator filtering and prioritization."""

    @pytest.fixture
    def filter(self):
        return IndicatorFilter()

    def test_skips_private_ips(self, filter):
        """Should skip private IP ranges."""
        ips = {"192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8"}
        
        filtered = filter.filter_indicators(
            ips=ips,
            domains=set(),
            detector_findings=[],
        )
        
        # Only public IP should remain
        values = {f.value for f in filtered}
        assert "192.168.1.1" not in values
        assert "10.0.0.1" not in values
        assert "172.16.0.1" not in values
        assert "8.8.8.8" in values

    def test_skips_loopback(self, filter):
        """Should skip loopback addresses."""
        ips = {"127.0.0.1", "1.1.1.1"}
        
        filtered = filter.filter_indicators(
            ips=ips,
            domains=set(),
            detector_findings=[],
        )
        
        values = {f.value for f in filtered}
        assert "127.0.0.1" not in values
        assert "1.1.1.1" in values

    def test_skips_known_safe_domains(self, filter):
        """Should skip known safe domains."""
        domains = {"www.google.com", "malicious-site.tk"}
        
        filtered = filter.filter_indicators(
            ips=set(),
            domains=domains,
            detector_findings=[],
        )
        
        values = {f.value for f in filtered}
        assert "www.google.com" not in values
        assert "malicious-site.tk" in values

    def test_prioritizes_detector_flagged(self, filter):
        """Should give higher priority to detector-flagged indicators."""
        # Create mock finding
        class MockFinding:
            detector = "beacon"
            affected_ips = ["45.33.32.156"]
            indicators = {}
        
        ips = {"8.8.8.8", "45.33.32.156"}
        
        filtered = filter.filter_indicators(
            ips=ips,
            domains=set(),
            detector_findings=[MockFinding()],
        )
        
        # Flagged IP should be HIGH priority
        flagged = next(f for f in filtered if f.value == "45.33.32.156")
        unflagged = next(f for f in filtered if f.value == "8.8.8.8")
        
        assert flagged.priority == IndicatorPriority.HIGH
        assert unflagged.priority == IndicatorPriority.MEDIUM


class TestEnrichmentCache:
    """Tests for the enrichment cache."""

    def test_cache_hit(self):
        """Should return cached results."""
        cache = EnrichmentCache()
        
        result = EnrichmentResult(
            indicator="8.8.8.8",
            indicator_type="ip",
        )
        result.virustotal = VirusTotalResult(
            indicator="8.8.8.8",
            indicator_type="ip",
            malicious_count=0,
            total_engines=90,
        )
        
        cache.set(result)
        
        cached = cache.get("8.8.8.8", "ip")
        assert cached is not None
        assert cached.indicator == "8.8.8.8"
        assert cached.cached is True

    def test_cache_miss(self):
        """Should return None for uncached indicators."""
        cache = EnrichmentCache()
        
        result = cache.get("not-cached.com", "domain")
        assert result is None

    def test_cache_stats(self):
        """Should track hit/miss statistics."""
        cache = EnrichmentCache()
        
        # Miss
        cache.get("test", "ip")
        
        # Set and hit
        result = EnrichmentResult(indicator="test", indicator_type="ip")
        cache.set(result)
        cache.get("test", "ip")
        
        stats = cache.stats
        assert stats["hits"] == 1
        assert stats["misses"] == 1


class TestThreatLevelModels:
    """Tests for enrichment result models."""

    def test_virustotal_threat_level_malicious(self):
        """VT result with many detections should be malicious."""
        result = VirusTotalResult(
            indicator="bad-ip",
            indicator_type="ip",
            malicious_count=12,
            harmless_count=70,
            undetected_count=8,
            total_engines=90,
        )
        
        assert result.threat_level == ThreatLevel.MALICIOUS
        assert result.detection_ratio == "12/90"

    def test_virustotal_threat_level_clean(self):
        """VT result with no detections should be clean."""
        result = VirusTotalResult(
            indicator="good-ip",
            indicator_type="ip",
            malicious_count=0,
            harmless_count=85,
            total_engines=90,
        )
        
        assert result.threat_level == ThreatLevel.CLEAN

    def test_abuseipdb_threat_level(self):
        """AbuseIPDB score maps to threat level correctly."""
        high_score = AbuseIPDBResult(ip_address="bad", abuse_confidence_score=90)
        mid_score = AbuseIPDBResult(ip_address="sus", abuse_confidence_score=50)
        low_score = AbuseIPDBResult(ip_address="good", abuse_confidence_score=0)
        
        assert high_score.threat_level == ThreatLevel.MALICIOUS
        assert mid_score.threat_level == ThreatLevel.SUSPICIOUS
        assert low_score.threat_level == ThreatLevel.CLEAN

    def test_overall_threat_level(self):
        """EnrichmentResult should aggregate threat levels correctly."""
        result = EnrichmentResult(indicator="test", indicator_type="ip")
        
        # Add one suspicious, one clean source
        result.virustotal = VirusTotalResult(
            indicator="test",
            indicator_type="ip",
            malicious_count=2,  # SUSPICIOUS
            total_engines=90,
        )
        result.abuseipdb = AbuseIPDBResult(
            ip_address="test",
            abuse_confidence_score=0,  # CLEAN
        )
        
        # Overall should be the most severe
        assert result.overall_threat_level == ThreatLevel.SUSPICIOUS

    def test_enrichment_result_serialization(self):
        """EnrichmentResult should serialize to dict."""
        result = EnrichmentResult(
            indicator="8.8.8.8",
            indicator_type="ip",
        )
        result.virustotal = VirusTotalResult(
            indicator="8.8.8.8",
            indicator_type="ip",
            malicious_count=0,
            total_engines=90,
            country="US",
        )
        
        data = result.to_dict()
        
        assert data["indicator"] == "8.8.8.8"
        assert data["overall_threat_level"] == "clean"
        assert data["sources"]["virustotal"]["country"] == "US"
