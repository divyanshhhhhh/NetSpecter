"""
NetSpecter Cascading Enrichment Module

Orchestrates threat intelligence enrichment using a cascading approach:
1. AlienVault OTX (10,000/hour) - Query ALL non-private indicators
2. AbuseIPDB (1,000/day) - Query only OTX-flagged IPs
3. VirusTotal (4/min) - Query only indicators flagged by OTX+AbuseIPDB

This approach maximizes detection while respecting API rate limits.
"""

import asyncio
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

import structlog

from backend.enrichment.abuseipdb import AbuseIPDBClient, get_abuseipdb_client
from backend.enrichment.models import (
    EnrichmentResult,
    OTXResult,
    AbuseIPDBResult,
    VirusTotalResult,
    ThreatLevel,
)
from backend.enrichment.otx import OTXClient, get_otx_client
from backend.enrichment.virustotal import VirusTotalClient, get_virustotal_client

logger = structlog.get_logger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Delay between requests to avoid rate limiting
REQUEST_DELAY_SECONDS = 0.5

# Maximum VirusTotal lookups per analysis
MAX_VT_LOOKUPS = 9

# Known safe domains to skip
KNOWN_SAFE_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com",
    "office365.com", "live.com", "amazon.com", "amazonaws.com",
    "cloudfront.net", "apple.com", "icloud.com", "facebook.com",
    "fbcdn.net", "twitter.com", "twimg.com", "github.com",
    "githubusercontent.com", "cloudflare.com", "akamai.net",
    "akamaitechnologies.com", "fastly.net", "akadns.net",
    "akamaiedge.net", "msedge.net", "azure.com", "bing.com",
}


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class CascadingStats:
    """Statistics from cascading enrichment run."""
    
    # OTX stats
    otx_total: int = 0
    otx_checked: int = 0
    otx_flagged: int = 0
    otx_errors: int = 0
    
    # AbuseIPDB stats
    abuseipdb_total: int = 0
    abuseipdb_checked: int = 0
    abuseipdb_flagged: int = 0
    abuseipdb_errors: int = 0
    
    # VirusTotal stats
    vt_total: int = 0
    vt_checked: int = 0
    vt_malicious: int = 0
    vt_errors: int = 0
    
    # Overall stats
    total_indicators: int = 0
    total_malicious: int = 0
    total_suspicious: int = 0
    duration_seconds: float = 0.0
    
    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "otx": {
                "total": self.otx_total,
                "checked": self.otx_checked,
                "flagged": self.otx_flagged,
                "errors": self.otx_errors,
            },
            "abuseipdb": {
                "total": self.abuseipdb_total,
                "checked": self.abuseipdb_checked,
                "flagged": self.abuseipdb_flagged,
                "errors": self.abuseipdb_errors,
            },
            "virustotal": {
                "total": self.vt_total,
                "checked": self.vt_checked,
                "malicious": self.vt_malicious,
                "errors": self.vt_errors,
            },
            "overall": {
                "total_indicators": self.total_indicators,
                "total_malicious": self.total_malicious,
                "total_suspicious": self.total_suspicious,
                "duration_seconds": self.duration_seconds,
            },
        }


@dataclass
class CascadingResult:
    """Result from cascading enrichment."""
    
    results: list[EnrichmentResult] = field(default_factory=list)
    stats: CascadingStats = field(default_factory=CascadingStats)
    flagged_indicators: list[dict] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "results": [r.to_dict() for r in self.results],
            "stats": self.stats.to_dict(),
            "flagged_indicators": self.flagged_indicators,
        }


# =============================================================================
# Progress Callbacks
# =============================================================================


@dataclass
class ProgressUpdate:
    """Progress update for UI callbacks."""
    
    step: str  # "otx", "abuseipdb", "virustotal"
    current: int
    total: int
    indicator: str
    indicator_type: str
    is_flagged: bool
    threat_level: str  # "malicious", "suspicious", "clean", "unknown"
    details: str = ""  # e.g., "3 pulses", "67% confidence"


ProgressCallback = Callable[[ProgressUpdate], None]


# =============================================================================
# Cascading Enrichment
# =============================================================================


class CascadingEnrichment:
    """
    Orchestrates cascading threat intelligence enrichment.
    
    Flow:
    1. OTX: Query all indicators (high rate limit)
    2. AbuseIPDB: Query OTX-flagged IPs only
    3. VirusTotal: Query indicators flagged by OTX+AbuseIPDB (max 10)
    """
    
    def __init__(
        self,
        otx_client: OTXClient | None = None,
        abuse_client: AbuseIPDBClient | None = None,
        vt_client: VirusTotalClient | None = None,
    ):
        """Initialize with API clients."""
        self.otx = otx_client or get_otx_client()
        self.abuse = abuse_client or get_abuseipdb_client()
        self.vt = vt_client or get_virustotal_client()
    
    @property
    def is_configured(self) -> bool:
        """Check if at least one API is configured."""
        return self.otx.is_configured or self.abuse.is_configured or self.vt.is_configured
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/reserved."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return (
                ip_obj.is_private or
                ip_obj.is_loopback or
                ip_obj.is_reserved or
                ip_obj.is_multicast or
                ip_obj.is_link_local
            )
        except ValueError:
            return True  # Invalid IP, skip it
    
    def _is_safe_domain(self, domain: str) -> bool:
        """Check if domain is known safe."""
        domain = domain.lower().strip(".")
        
        # Skip empty or local domains
        if not domain or domain.endswith((".local", ".lan", ".internal", ".localhost")):
            return True
        
        # Skip reverse DNS
        if domain.endswith((".in-addr.arpa", ".ip6.arpa")):
            return True
        
        # Check against known safe list
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in KNOWN_SAFE_DOMAINS:
                return True
        
        return False
    
    def _is_otx_flagged(self, result: OTXResult) -> bool:
        """Check if OTX result indicates a threat."""
        if result.error:
            return False
        return result.pulse_count >= 1 or len(result.malware_families) > 0
    
    def _is_abuseipdb_flagged(self, result: AbuseIPDBResult) -> bool:
        """Check if AbuseIPDB result indicates a threat."""
        if result.error:
            return False
        return result.abuse_confidence_score >= 25 or result.total_reports >= 3
    
    def _get_otx_details(self, result: OTXResult) -> str:
        """Get details string from OTX result."""
        parts = []
        if result.pulse_count > 0:
            parts.append(f"{result.pulse_count} pulses")
        if result.malware_families:
            parts.append(", ".join(result.malware_families[:3]))
        return " - ".join(parts) if parts else ""
    
    def _get_abuse_details(self, result: AbuseIPDBResult) -> str:
        """Get details string from AbuseIPDB result."""
        parts = []
        if result.abuse_confidence_score > 0:
            parts.append(f"{result.abuse_confidence_score}% confidence")
        if result.total_reports > 0:
            parts.append(f"{result.total_reports} reports")
        if result.category_names:
            parts.append(", ".join(result.category_names[:2]))
        return " - ".join(parts) if parts else ""
    
    def _get_vt_details(self, result: VirusTotalResult) -> str:
        """Get details string from VirusTotal result."""
        parts = [result.detection_ratio]
        if result.tags:
            parts.append(", ".join(result.tags[:3]))
        return " - ".join(parts)
    
    async def run(
        self,
        ips: set[str],
        domains: set[str],
        typosquat_suspects: set[str] | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> CascadingResult:
        """
        Run cascading enrichment on pre-filtered indicators.
        
        Args:
            ips: Set of public IP addresses to check (already filtered by SmartIndicatorFilter)
            domains: Set of domains to check (already filtered)
            typosquat_suspects: Set of domains flagged as potential typosquatting
            progress_callback: Optional callback for progress updates
        
        Returns:
            CascadingResult with all enrichment data
        """
        start_time = datetime.now()
        stats = CascadingStats()
        
        # Convert to lists for iteration (already filtered by SmartIndicatorFilter)
        filtered_ips = list(ips)
        filtered_domains = list(domains)
        typosquats = typosquat_suspects or set()
        
        stats.total_indicators = len(filtered_ips) + len(filtered_domains)
        stats.otx_total = stats.total_indicators
        
        logger.info(
            "cascading_enrichment_start",
            total_ips=len(filtered_ips),
            total_domains=len(filtered_domains),
            typosquats=len(typosquats),
        )
        
        # Storage for results
        enrichment_results: dict[str, EnrichmentResult] = {}
        flagged_indicators: list[dict] = []
        
        # =====================================================================
        # Step 1: AlienVault OTX (all indicators)
        # =====================================================================
        otx_flagged_ips: set[str] = set()
        otx_flagged_domains: set[str] = set()
        
        if self.otx.is_configured:
            # Process IPs
            for i, ip in enumerate(filtered_ips, 1):
                try:
                    result = await self.otx.lookup_ip(ip)
                    stats.otx_checked += 1
                    
                    is_flagged = self._is_otx_flagged(result)
                    if is_flagged:
                        stats.otx_flagged += 1
                        otx_flagged_ips.add(ip)
                    
                    # Store result
                    enrichment_results[ip] = EnrichmentResult(
                        indicator=ip,
                        indicator_type="ip",
                        otx=result,
                    )
                    
                    # Progress callback
                    if progress_callback:
                        progress_callback(ProgressUpdate(
                            step="otx",
                            current=i,
                            total=len(filtered_ips) + len(filtered_domains),
                            indicator=ip,
                            indicator_type="ip",
                            is_flagged=is_flagged,
                            threat_level=result.threat_level.value,
                            details=self._get_otx_details(result),
                        ))
                    
                    # Rate limit delay
                    await asyncio.sleep(REQUEST_DELAY_SECONDS)
                    
                except Exception as e:
                    logger.error("otx_ip_error", ip=ip, error=str(e))
                    stats.otx_errors += 1
            
            # Process domains
            for i, domain in enumerate(filtered_domains, 1):
                try:
                    result = await self.otx.lookup_domain(domain)
                    stats.otx_checked += 1
                    
                    is_flagged = self._is_otx_flagged(result)
                    if is_flagged:
                        stats.otx_flagged += 1
                        otx_flagged_domains.add(domain)
                    
                    # Store result
                    enrichment_results[domain] = EnrichmentResult(
                        indicator=domain,
                        indicator_type="domain",
                        otx=result,
                    )
                    
                    # Progress callback
                    if progress_callback:
                        progress_callback(ProgressUpdate(
                            step="otx",
                            current=len(filtered_ips) + i,
                            total=len(filtered_ips) + len(filtered_domains),
                            indicator=domain,
                            indicator_type="domain",
                            is_flagged=is_flagged,
                            threat_level=result.threat_level.value,
                            details=self._get_otx_details(result),
                        ))
                    
                    # Rate limit delay
                    await asyncio.sleep(REQUEST_DELAY_SECONDS)
                    
                except Exception as e:
                    logger.error("otx_domain_error", domain=domain, error=str(e))
                    stats.otx_errors += 1
        
        # =====================================================================
        # Step 2: AbuseIPDB (OTX-flagged IPs only)
        # =====================================================================
        abuseipdb_flagged_ips: set[str] = set()
        
        if self.abuse.is_configured:
            # Include OTX-flagged IPs + IPs with no OTX data (if OTX not configured)
            ips_for_abuse = otx_flagged_ips.copy()
            if not self.otx.is_configured:
                ips_for_abuse = set(filtered_ips)
            
            stats.abuseipdb_total = len(ips_for_abuse)
            
            for i, ip in enumerate(ips_for_abuse, 1):
                try:
                    result = await self.abuse.check_ip(ip)
                    stats.abuseipdb_checked += 1
                    
                    is_flagged = self._is_abuseipdb_flagged(result)
                    if is_flagged:
                        stats.abuseipdb_flagged += 1
                        abuseipdb_flagged_ips.add(ip)
                    
                    # Update enrichment result
                    if ip in enrichment_results:
                        enrichment_results[ip].abuseipdb = result
                    else:
                        enrichment_results[ip] = EnrichmentResult(
                            indicator=ip,
                            indicator_type="ip",
                            abuseipdb=result,
                        )
                    
                    # Progress callback
                    if progress_callback:
                        progress_callback(ProgressUpdate(
                            step="abuseipdb",
                            current=i,
                            total=len(ips_for_abuse),
                            indicator=ip,
                            indicator_type="ip",
                            is_flagged=is_flagged,
                            threat_level=result.threat_level.value,
                            details=self._get_abuse_details(result),
                        ))
                    
                    # Rate limit delay
                    await asyncio.sleep(REQUEST_DELAY_SECONDS)
                    
                except Exception as e:
                    logger.error("abuseipdb_error", ip=ip, error=str(e))
                    stats.abuseipdb_errors += 1
        
        # =====================================================================
        # Step 3: VirusTotal (flagged indicators only, max 10)
        # =====================================================================
        if self.vt.is_configured:
            # Combine flagged indicators from OTX and AbuseIPDB
            vt_candidates: list[tuple[str, str]] = []  # (indicator, type)
            
            # Add IPs flagged by both OTX and AbuseIPDB first (highest priority)
            for ip in otx_flagged_ips & abuseipdb_flagged_ips:
                vt_candidates.append((ip, "ip"))
            
            # Add IPs flagged by AbuseIPDB only
            for ip in abuseipdb_flagged_ips - otx_flagged_ips:
                vt_candidates.append((ip, "ip"))
            
            # Add IPs flagged by OTX only
            for ip in otx_flagged_ips - abuseipdb_flagged_ips:
                vt_candidates.append((ip, "ip"))
            
            # Add domains flagged by OTX (skip to VT since AbuseIPDB doesn't support domains)
            for domain in otx_flagged_domains:
                vt_candidates.append((domain, "domain"))
            
            # Limit to MAX_VT_LOOKUPS
            vt_candidates = vt_candidates[:MAX_VT_LOOKUPS]
            stats.vt_total = len(vt_candidates)
            
            for i, (indicator, ind_type) in enumerate(vt_candidates, 1):
                try:
                    result = await self.vt.lookup(indicator, ind_type)
                    stats.vt_checked += 1
                    
                    is_malicious = (
                        result.malicious_count >= 1 or 
                        result.threat_level == ThreatLevel.MALICIOUS
                    )
                    if is_malicious:
                        stats.vt_malicious += 1
                    
                    # Update enrichment result
                    if indicator in enrichment_results:
                        enrichment_results[indicator].virustotal = result
                    else:
                        enrichment_results[indicator] = EnrichmentResult(
                            indicator=indicator,
                            indicator_type=ind_type,
                            virustotal=result,
                        )
                    
                    # Progress callback
                    if progress_callback:
                        progress_callback(ProgressUpdate(
                            step="virustotal",
                            current=i,
                            total=len(vt_candidates),
                            indicator=indicator,
                            indicator_type=ind_type,
                            is_flagged=is_malicious,
                            threat_level=result.threat_level.value,
                            details=self._get_vt_details(result),
                        ))
                    
                    # VT rate limit is 4/min, but we already have built-in rate limiting
                    # No additional delay needed
                    
                except Exception as e:
                    logger.error("virustotal_error", indicator=indicator, error=str(e))
                    stats.vt_errors += 1
        
        # =====================================================================
        # Build flagged indicators list
        # =====================================================================
        for indicator, result in enrichment_results.items():
            threat_level = result.overall_threat_level
            
            if threat_level in (ThreatLevel.MALICIOUS, ThreatLevel.SUSPICIOUS):
                if threat_level == ThreatLevel.MALICIOUS:
                    stats.total_malicious += 1
                else:
                    stats.total_suspicious += 1
                
                # Build summary
                sources = []
                if result.virustotal and result.virustotal.malicious_count > 0:
                    sources.append(f"VT: {result.virustotal.detection_ratio}")
                if result.abuseipdb and result.abuseipdb.abuse_confidence_score > 0:
                    sources.append(f"AbuseIPDB: {result.abuseipdb.abuse_confidence_score}%")
                if result.otx and result.otx.pulse_count > 0:
                    sources.append(f"OTX: {result.otx.pulse_count} pulses")
                
                malware_families = []
                if result.otx and result.otx.malware_families:
                    malware_families = result.otx.malware_families[:3]
                if result.virustotal and result.virustotal.tags:
                    malware_families.extend(result.virustotal.tags[:2])
                
                flagged_indicators.append({
                    "indicator": indicator,
                    "indicator_type": result.indicator_type,
                    "threat_level": threat_level.value,
                    "sources": sources,
                    "malware_families": list(set(malware_families)),
                    "summary": " | ".join(sources),
                })
        
        # Sort flagged indicators: malicious first, then by source count
        flagged_indicators.sort(
            key=lambda x: (
                0 if x["threat_level"] == "malicious" else 1,
                -len(x["sources"]),
            )
        )
        
        # Calculate duration
        stats.duration_seconds = (datetime.now() - start_time).total_seconds()
        
        logger.info(
            "cascading_enrichment_complete",
            duration=stats.duration_seconds,
            total_malicious=stats.total_malicious,
            total_suspicious=stats.total_suspicious,
        )
        
        return CascadingResult(
            results=list(enrichment_results.values()),
            stats=stats,
            flagged_indicators=flagged_indicators,
        )


# =============================================================================
# Singleton Instance
# =============================================================================

_enrichment_instance: CascadingEnrichment | None = None


def get_cascading_enrichment() -> CascadingEnrichment:
    """Get the singleton cascading enrichment instance."""
    global _enrichment_instance
    if _enrichment_instance is None:
        _enrichment_instance = CascadingEnrichment()
    return _enrichment_instance
