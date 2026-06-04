"""
NetSpecter Enrichment Manager

Orchestrates threat intelligence enrichment from multiple sources.
Handles caching, rate limiting, and result aggregation.

Two-phase enrichment strategy:
1. Fast Phase: Query AbuseIPDB and OTX for ALL indicators (no rate limit issues)
2. Smart Phase: Use AI to select 8-12 most suspicious indicators for VirusTotal
   This limits VT wait time to ~3 min instead of ~11 min for 44 indicators
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any

import structlog

from backend.config import settings
from backend.enrichment.cache import EnrichmentCache, get_enrichment_cache
from backend.enrichment.filter import FilteredIndicator, IndicatorFilter, IndicatorPriority
from backend.enrichment.models import EnrichmentResult, ThreatLevel
from backend.enrichment.virustotal import VirusTotalClient, get_virustotal_client
from backend.enrichment.abuseipdb import AbuseIPDBClient, get_abuseipdb_client
from backend.enrichment.otx import OTXClient, get_otx_client
from backend.enrichment.prioritizer import prioritize_for_virustotal, MAX_VT_INDICATORS

logger = structlog.get_logger(__name__)


@dataclass
class EnrichmentStats:
    """Statistics from an enrichment run."""
    
    total_indicators: int = 0
    cached_hits: int = 0
    api_lookups: int = 0
    virustotal_queries: int = 0
    virustotal_skipped: int = 0  # Indicators skipped by AI prioritization
    abuseipdb_queries: int = 0
    otx_queries: int = 0
    malicious_found: int = 0
    suspicious_found: int = 0
    errors: int = 0
    duration_seconds: float = 0.0
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "total_indicators": self.total_indicators,
            "cached_hits": self.cached_hits,
            "api_lookups": self.api_lookups,
            "virustotal_queries": self.virustotal_queries,
            "virustotal_skipped": self.virustotal_skipped,
            "abuseipdb_queries": self.abuseipdb_queries,
            "otx_queries": self.otx_queries,
            "malicious_found": self.malicious_found,
            "suspicious_found": self.suspicious_found,
            "errors": self.errors,
            "duration_seconds": round(self.duration_seconds, 2),
        }


@dataclass
class EnrichmentSummary:
    """Summary of enrichment results."""
    
    results: list[EnrichmentResult] = field(default_factory=list)
    stats: EnrichmentStats = field(default_factory=EnrichmentStats)
    
    @property
    def malicious_indicators(self) -> list[EnrichmentResult]:
        """Get all indicators classified as malicious."""
        return [
            r for r in self.results
            if r.overall_threat_level == ThreatLevel.MALICIOUS
        ]
    
    @property
    def suspicious_indicators(self) -> list[EnrichmentResult]:
        """Get all indicators classified as suspicious."""
        return [
            r for r in self.results
            if r.overall_threat_level == ThreatLevel.SUSPICIOUS
        ]
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "results": [r.to_dict() for r in self.results],
            "stats": self.stats.to_dict(),
            "malicious_count": len(self.malicious_indicators),
            "suspicious_count": len(self.suspicious_indicators),
        }


class EnrichmentManager:
    """
    Manages threat intelligence enrichment.
    
    Coordinates between:
    - Indicator filtering and prioritization
    - Caching layer
    - Multiple threat intel APIs
    - Result aggregation
    """
    
    def __init__(
        self,
        cache: EnrichmentCache | None = None,
        vt_client: VirusTotalClient | None = None,
        abuse_client: AbuseIPDBClient | None = None,
        otx_client: OTXClient | None = None,
        max_concurrent: int = 5,
    ):
        """
        Initialize the manager.
        
        Args:
            cache: Enrichment cache (uses global if not provided)
            vt_client: VirusTotal client
            abuse_client: AbuseIPDB client
            otx_client: OTX client
            max_concurrent: Maximum concurrent API requests
        """
        self.cache = cache or get_enrichment_cache()
        self.vt_client = vt_client or get_virustotal_client()
        self.abuse_client = abuse_client or get_abuseipdb_client()
        self.otx_client = otx_client or get_otx_client()
        self.max_concurrent = max_concurrent
        
        # Semaphore to limit concurrent requests
        self._semaphore = asyncio.Semaphore(max_concurrent)
    
    @property
    def is_configured(self) -> bool:
        """Check if any API is configured."""
        return (
            self.vt_client.is_configured or
            self.abuse_client.is_configured or
            self.otx_client.is_configured
        )
    
    async def enrich_indicators(
        self,
        ips: set[str],
        domains: set[str],
        detector_findings: list[Any],
        filter_config: dict[str, Any] | None = None,
    ) -> EnrichmentSummary:
        """
        Enrich a set of indicators with threat intelligence.
        
        Args:
            ips: Set of IP addresses from traffic
            domains: Set of domains from DNS/TLS data
            detector_findings: List of Finding objects from detectors
            filter_config: Optional configuration for the indicator filter
        
        Returns:
            EnrichmentSummary with all results and statistics
        """
        import time
        start_time = time.time()
        
        stats = EnrichmentStats()
        results: list[EnrichmentResult] = []
        
        if not self.is_configured:
            logger.info("enrichment_skipped", reason="No API keys configured")
            return EnrichmentSummary(results=[], stats=stats)
        
        # Filter and prioritize indicators
        filter_config = filter_config or {}
        indicator_filter = IndicatorFilter(**filter_config)
        
        filtered = indicator_filter.filter_indicators(
            ips=ips,
            domains=domains,
            detector_findings=detector_findings,
        )
        
        stats.total_indicators = len(filtered)
        
        if not filtered:
            logger.info("enrichment_skipped", reason="No indicators to enrich")
            return EnrichmentSummary(results=[], stats=stats)
        
        # Check cache first
        to_lookup: list[FilteredIndicator] = []
        for indicator in filtered:
            cached = self.cache.get(indicator.value, indicator.indicator_type)
            if cached:
                results.append(cached)
                stats.cached_hits += 1
            else:
                to_lookup.append(indicator)
        
        stats.api_lookups = len(to_lookup)
        
        logger.info(
            "enrichment_starting",
            total=stats.total_indicators,
            cached=stats.cached_hits,
            to_lookup=len(to_lookup),
        )
        
        # Look up uncached indicators
        if to_lookup:
            lookup_results = await self._batch_lookup(to_lookup, stats)
            
            # Cache and add results
            for result in lookup_results:
                self.cache.set(result)
                results.append(result)
                
                # Count threat levels
                if result.overall_threat_level == ThreatLevel.MALICIOUS:
                    stats.malicious_found += 1
                elif result.overall_threat_level == ThreatLevel.SUSPICIOUS:
                    stats.suspicious_found += 1
        
        stats.duration_seconds = time.time() - start_time
        
        # Sort results by threat level
        threat_order = {
            ThreatLevel.MALICIOUS: 0,
            ThreatLevel.SUSPICIOUS: 1,
            ThreatLevel.UNKNOWN: 2,
            ThreatLevel.CLEAN: 3,
        }
        results.sort(key=lambda r: threat_order.get(r.overall_threat_level, 99))
        
        logger.info(
            "enrichment_complete",
            total=stats.total_indicators,
            malicious=stats.malicious_found,
            suspicious=stats.suspicious_found,
            duration=round(stats.duration_seconds, 2),
        )
        
        return EnrichmentSummary(results=results, stats=stats)
    
    async def _batch_lookup(
        self,
        indicators: list[FilteredIndicator],
        stats: EnrichmentStats,
    ) -> list[EnrichmentResult]:
        """
        Look up multiple indicators using two-phase smart enrichment.
        
        Phase 1: Query AbuseIPDB and OTX for ALL indicators (fast, no rate limit)
        Phase 2: Use AI to select top 8-12 indicators for VirusTotal (slow API)
        
        This reduces VT wait time from ~11 min (44 indicators) to ~3 min max.
        
        Args:
            indicators: List of indicators to look up
            stats: Stats object to update
        
        Returns:
            List of EnrichmentResult objects
        """
        # Initialize results for all indicators
        results_map: dict[str, EnrichmentResult] = {}
        for ind in indicators:
            results_map[ind.value] = EnrichmentResult(
                indicator=ind.value,
                indicator_type=ind.indicator_type,
            )
        
        # =========================================================
        # Phase 1: Fast lookups (AbuseIPDB + OTX) for ALL indicators
        # =========================================================
        logger.info(
            "enrichment_phase1_start",
            message="Fast enrichment phase (AbuseIPDB + OTX)",
            indicator_count=len(indicators),
        )
        
        phase1_tasks = []
        for ind in indicators:
            phase1_tasks.append(self._lookup_fast_sources(ind, stats))
        
        phase1_results = await asyncio.gather(*phase1_tasks, return_exceptions=True)
        
        # Merge Phase 1 results
        for i, result in enumerate(phase1_results):
            if isinstance(result, Exception):
                logger.error("enrichment_phase1_error", error=str(result))
                stats.errors += 1
                continue
            if result:
                ind_value = indicators[i].value
                results_map[ind_value] = result
        
        logger.info(
            "enrichment_phase1_complete",
            abuseipdb_queries=stats.abuseipdb_queries,
            otx_queries=stats.otx_queries,
        )
        
        # =========================================================
        # Phase 2: AI-prioritized VirusTotal lookups (max 8-12)
        # =========================================================
        if self.vt_client.is_configured:
            indicator_values = [ind.value for ind in indicators]
            
            # Use AI to select which indicators need VT validation
            prioritized = await prioritize_for_virustotal(
                indicators=indicator_values,
                preliminary_results=results_map,
                max_selections=MAX_VT_INDICATORS,
            )
            
            stats.virustotal_skipped = prioritized.skipped_count
            
            logger.info(
                "enrichment_phase2_start",
                message="VirusTotal phase (AI-prioritized)",
                selected=len(prioritized.selected),
                skipped=prioritized.skipped_count,
            )
            
            # Look up selected indicators in VirusTotal
            for indicator_value in prioritized.selected:
                # Find the indicator type
                ind_type = "ip"
                for ind in indicators:
                    if ind.value == indicator_value:
                        ind_type = ind.indicator_type
                        break
                
                try:
                    vt_result = await self.vt_client.lookup(indicator_value, ind_type)
                    if vt_result:
                        results_map[indicator_value].virustotal = vt_result
                        stats.virustotal_queries += 1
                except Exception as e:
                    logger.warning(
                        "enrichment_vt_error",
                        indicator=indicator_value,
                        error=str(e),
                    )
                    stats.errors += 1
            
            logger.info(
                "enrichment_phase2_complete",
                virustotal_queries=stats.virustotal_queries,
            )
        
        # Return all results
        return list(results_map.values())
    
    async def _lookup_fast_sources(
        self,
        indicator: FilteredIndicator,
        stats: EnrichmentStats,
    ) -> EnrichmentResult:
        """
        Look up indicator from fast sources (AbuseIPDB, OTX).
        
        These sources have high rate limits so we can query all indicators.
        
        Args:
            indicator: The indicator to look up
            stats: Stats object to update
        
        Returns:
            EnrichmentResult with fast source data
        """
        async with self._semaphore:
            result = EnrichmentResult(
                indicator=indicator.value,
                indicator_type=indicator.indicator_type,
            )
            
            tasks = []
            
            # AbuseIPDB only supports IPs
            if self.abuse_client.is_configured and indicator.indicator_type == "ip":
                tasks.append(("abuse", self.abuse_client.lookup(
                    indicator.value,
                    indicator.indicator_type,
                )))
            
            # OTX supports both IPs and domains
            if self.otx_client.is_configured:
                tasks.append(("otx", self.otx_client.lookup(
                    indicator.value,
                    indicator.indicator_type,
                )))
            
            if not tasks:
                return result
            
            # Execute lookups in parallel
            lookups = await asyncio.gather(
                *[t[1] for t in tasks],
                return_exceptions=True,
            )
            
            # Process results
            for i, (source, _) in enumerate(tasks):
                lookup_result = lookups[i]
                
                if isinstance(lookup_result, Exception):
                    logger.warning(
                        "enrichment_fast_source_error",
                        source=source,
                        indicator=indicator.value,
                        error=str(lookup_result),
                    )
                    stats.errors += 1
                    continue
                
                if source == "abuse" and lookup_result:
                    result.abuseipdb = lookup_result
                    stats.abuseipdb_queries += 1
                elif source == "otx" and lookup_result:
                    result.otx = lookup_result
                    stats.otx_queries += 1
            
            return result
    
    async def _lookup_single(
        self,
        indicator: FilteredIndicator,
        stats: EnrichmentStats,
    ) -> EnrichmentResult:
        """
        Look up a single indicator from all sources.
        
        Args:
            indicator: The indicator to look up
            stats: Stats object to update
        
        Returns:
            Aggregated EnrichmentResult
        """
        async with self._semaphore:
            result = EnrichmentResult(
                indicator=indicator.value,
                indicator_type=indicator.indicator_type,
            )
            
            # Parallel lookups to all configured sources
            tasks = []
            
            if self.vt_client.is_configured:
                tasks.append(("vt", self.vt_client.lookup(
                    indicator.value,
                    indicator.indicator_type,
                )))
            
            if self.abuse_client.is_configured and indicator.indicator_type == "ip":
                tasks.append(("abuse", self.abuse_client.lookup(
                    indicator.value,
                    indicator.indicator_type,
                )))
            
            if self.otx_client.is_configured:
                tasks.append(("otx", self.otx_client.lookup(
                    indicator.value,
                    indicator.indicator_type,
                )))
            
            if not tasks:
                return result
            
            # Execute lookups
            lookups = await asyncio.gather(
                *[t[1] for t in tasks],
                return_exceptions=True,
            )
            
            # Assign results
            for i, (source, _) in enumerate(tasks):
                lookup_result = lookups[i]
                
                if isinstance(lookup_result, Exception):
                    logger.warning(
                        "enrichment_source_error",
                        source=source,
                        indicator=indicator.value,
                        error=str(lookup_result),
                    )
                    stats.errors += 1
                    continue
                
                if source == "vt" and lookup_result:
                    result.virustotal = lookup_result
                    stats.virustotal_queries += 1
                elif source == "abuse" and lookup_result:
                    result.abuseipdb = lookup_result
                    stats.abuseipdb_queries += 1
                elif source == "otx" and lookup_result:
                    result.otx = lookup_result
                    stats.otx_queries += 1
            
            logger.debug(
                "indicator_enriched",
                indicator=indicator.value,
                threat_level=result.overall_threat_level.value,
                sources=result.source_count,
            )
            
            return result
    
    async def enrich_single(
        self,
        indicator: str,
        indicator_type: str,
    ) -> EnrichmentResult:
        """
        Enrich a single indicator.
        
        Args:
            indicator: IP or domain to enrich
            indicator_type: "ip" or "domain"
        
        Returns:
            EnrichmentResult with all available data
        """
        # Check cache
        cached = self.cache.get(indicator, indicator_type)
        if cached:
            return cached
        
        # Create a filtered indicator for lookup
        filtered = FilteredIndicator(
            value=indicator,
            indicator_type=indicator_type,
            priority=IndicatorPriority.HIGH,
            reason="Direct lookup",
        )
        
        stats = EnrichmentStats()
        result = await self._lookup_single(filtered, stats)
        
        # Cache the result
        self.cache.set(result)
        
        return result


# Singleton instance
_manager_instance: EnrichmentManager | None = None


def get_enrichment_manager() -> EnrichmentManager:
    """Get or create the global enrichment manager."""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = EnrichmentManager()
    return _manager_instance
