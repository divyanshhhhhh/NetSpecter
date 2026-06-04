"""
NetSpecter Indicator Filter

Classifies and prioritizes indicators (IPs/domains) for threat intelligence lookup.
Filters out private ranges, loopback, and known-safe infrastructure.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class IndicatorPriority(Enum):
    """Priority level for threat intelligence lookup."""
    
    SKIP = "skip"  # Don't query (private, loopback, etc.)
    LOW = "low"  # Query if budget allows
    MEDIUM = "medium"  # Query with normal priority
    HIGH = "high"  # Query immediately (flagged by detectors)
    CRITICAL = "critical"  # Must query (multiple detector hits)


# Known CDN and cloud provider ranges (simplified)
# In production, use a proper IP range database
KNOWN_CDN_RANGES = [
    # Cloudflare
    "104.16.0.0/12",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    # Akamai (sample ranges)
    "23.0.0.0/12",
    "23.192.0.0/11",
    # Fastly
    "151.101.0.0/16",
    # Google Cloud CDN
    "34.0.0.0/8",
    # AWS CloudFront (sample)
    "13.32.0.0/15",
    "13.35.0.0/16",
    # Microsoft Azure CDN
    "13.107.0.0/16",
]

# Known safe domains (major providers)
KNOWN_SAFE_DOMAINS = {
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "youtube.com",
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",
    "office.com",
    "office365.com",
    "live.com",
    "amazon.com",
    "amazonaws.com",
    "cloudfront.net",
    "apple.com",
    "icloud.com",
    "facebook.com",
    "fbcdn.net",
    "twitter.com",
    "twimg.com",
    "github.com",
    "githubusercontent.com",
    "cloudflare.com",
    "akamai.net",
    "akamaitechnologies.com",
    "fastly.net",
}


@dataclass
class FilteredIndicator:
    """An indicator with its assigned priority."""
    
    value: str
    indicator_type: str  # "ip" or "domain"
    priority: IndicatorPriority
    reason: str  # Why this priority was assigned
    source_detectors: list[str] = field(default_factory=list)  # Which detectors flagged this
    detection_count: int = 0  # How many times it appeared in findings


class IndicatorFilter:
    """
    Filters and prioritizes indicators for threat intelligence lookup.
    
    Reduces API queries by:
    - Skipping private/reserved IP ranges
    - Skipping known-safe infrastructure (CDNs, major providers)
    - Prioritizing detector-flagged indicators
    - Limiting total queries to stay within rate limits
    """
    
    def __init__(
        self,
        max_high_priority: int = 5,
        max_medium_priority: int = 10,
        max_low_priority: int = 5,
        skip_cdn_ips: bool = True,
        skip_safe_domains: bool = True,
    ):
        """
        Initialize the filter.
        
        Args:
            max_high_priority: Maximum high-priority indicators to return
            max_medium_priority: Maximum medium-priority indicators to return
            max_low_priority: Maximum low-priority indicators to return
            skip_cdn_ips: Whether to skip known CDN IP ranges
            skip_safe_domains: Whether to skip known safe domains
        """
        self.max_high = max_high_priority
        self.max_medium = max_medium_priority
        self.max_low = max_low_priority
        self.skip_cdn_ips = skip_cdn_ips
        self.skip_safe_domains = skip_safe_domains
        
        # Pre-compile CDN network objects
        self._cdn_networks = []
        if skip_cdn_ips:
            for cidr in KNOWN_CDN_RANGES:
                try:
                    self._cdn_networks.append(ipaddress.ip_network(cidr))
                except ValueError:
                    pass
    
    def filter_indicators(
        self,
        ips: set[str],
        domains: set[str],
        detector_findings: list[Any],
    ) -> list[FilteredIndicator]:
        """
        Filter and prioritize indicators for lookup.
        
        Args:
            ips: Set of IP addresses from traffic
            domains: Set of domains from DNS/TLS data
            detector_findings: List of Finding objects from detectors
        
        Returns:
            Prioritized list of FilteredIndicator objects
        """
        # Track which indicators are flagged by detectors
        flagged_ips: dict[str, list[str]] = {}  # ip -> [detector names]
        flagged_domains: dict[str, list[str]] = {}  # domain -> [detector names]
        
        for finding in detector_findings:
            detector_name = finding.detector
            
            # Collect IPs from findings
            for ip in getattr(finding, 'affected_ips', []):
                if ip not in flagged_ips:
                    flagged_ips[ip] = []
                flagged_ips[ip].append(detector_name)
            
            # Check indicators dict for domains
            indicators = getattr(finding, 'indicators', {})
            if 'domain' in indicators:
                domain = indicators['domain']
                if domain not in flagged_domains:
                    flagged_domains[domain] = []
                flagged_domains[domain].append(detector_name)
        
        results: list[FilteredIndicator] = []
        
        # Process IPs
        for ip in ips:
            filtered = self._classify_ip(ip, flagged_ips.get(ip, []))
            if filtered.priority != IndicatorPriority.SKIP:
                results.append(filtered)
        
        # Process domains
        for domain in domains:
            filtered = self._classify_domain(domain, flagged_domains.get(domain, []))
            if filtered.priority != IndicatorPriority.SKIP:
                results.append(filtered)
        
        # Sort by priority (CRITICAL > HIGH > MEDIUM > LOW)
        priority_order = {
            IndicatorPriority.CRITICAL: 0,
            IndicatorPriority.HIGH: 1,
            IndicatorPriority.MEDIUM: 2,
            IndicatorPriority.LOW: 3,
        }
        results.sort(key=lambda x: (priority_order.get(x.priority, 99), -x.detection_count))
        
        # Apply limits
        limited_results = self._apply_limits(results)
        
        logger.info(
            "indicators_filtered",
            total_ips=len(ips),
            total_domains=len(domains),
            flagged_ips=len(flagged_ips),
            flagged_domains=len(flagged_domains),
            output_count=len(limited_results),
        )
        
        return limited_results
    
    def _classify_ip(self, ip: str, detectors: list[str]) -> FilteredIndicator:
        """Classify an IP address."""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return FilteredIndicator(
                value=ip,
                indicator_type="ip",
                priority=IndicatorPriority.SKIP,
                reason="Invalid IP format",
            )
        
        # Check if private
        if ip_obj.is_private:
            return FilteredIndicator(
                value=ip,
                indicator_type="ip",
                priority=IndicatorPriority.SKIP,
                reason="Private IP range",
            )
        
        # Check if loopback
        if ip_obj.is_loopback:
            return FilteredIndicator(
                value=ip,
                indicator_type="ip",
                priority=IndicatorPriority.SKIP,
                reason="Loopback address",
            )
        
        # Check if reserved/special
        if ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_link_local:
            return FilteredIndicator(
                value=ip,
                indicator_type="ip",
                priority=IndicatorPriority.SKIP,
                reason="Reserved/special address",
            )
        
        # Check CDN ranges
        if self.skip_cdn_ips:
            for network in self._cdn_networks:
                if ip_obj in network:
                    return FilteredIndicator(
                        value=ip,
                        indicator_type="ip",
                        priority=IndicatorPriority.SKIP,
                        reason=f"Known CDN range ({network})",
                    )
        
        # Determine priority based on detector flags
        if len(detectors) >= 2:
            return FilteredIndicator(
                value=ip,
                indicator_type="ip",
                priority=IndicatorPriority.CRITICAL,
                reason=f"Flagged by {len(detectors)} detectors",
                source_detectors=detectors,
                detection_count=len(detectors),
            )
        elif len(detectors) == 1:
            return FilteredIndicator(
                value=ip,
                indicator_type="ip",
                priority=IndicatorPriority.HIGH,
                reason=f"Flagged by {detectors[0]}",
                source_detectors=detectors,
                detection_count=1,
            )
        else:
            return FilteredIndicator(
                value=ip,
                indicator_type="ip",
                priority=IndicatorPriority.MEDIUM,
                reason="External IP from traffic",
            )
    
    def _classify_domain(self, domain: str, detectors: list[str]) -> FilteredIndicator:
        """Classify a domain."""
        domain = domain.lower().strip(".")
        
        # Skip empty
        if not domain:
            return FilteredIndicator(
                value=domain,
                indicator_type="domain",
                priority=IndicatorPriority.SKIP,
                reason="Empty domain",
            )
        
        # Check known safe domains
        if self.skip_safe_domains:
            # Check if domain or parent is in safe list
            parts = domain.split(".")
            for i in range(len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in KNOWN_SAFE_DOMAINS:
                    return FilteredIndicator(
                        value=domain,
                        indicator_type="domain",
                        priority=IndicatorPriority.SKIP,
                        reason=f"Known safe domain ({parent})",
                    )
        
        # Skip reverse DNS lookups
        if domain.endswith(".in-addr.arpa") or domain.endswith(".ip6.arpa"):
            return FilteredIndicator(
                value=domain,
                indicator_type="domain",
                priority=IndicatorPriority.SKIP,
                reason="Reverse DNS lookup",
            )
        
        # Skip local domains
        if domain.endswith(".local") or domain.endswith(".lan") or domain.endswith(".internal"):
            return FilteredIndicator(
                value=domain,
                indicator_type="domain",
                priority=IndicatorPriority.SKIP,
                reason="Local domain",
            )
        
        # Determine priority based on detector flags
        if len(detectors) >= 2:
            return FilteredIndicator(
                value=domain,
                indicator_type="domain",
                priority=IndicatorPriority.CRITICAL,
                reason=f"Flagged by {len(detectors)} detectors",
                source_detectors=detectors,
                detection_count=len(detectors),
            )
        elif len(detectors) == 1:
            return FilteredIndicator(
                value=domain,
                indicator_type="domain",
                priority=IndicatorPriority.HIGH,
                reason=f"Flagged by {detectors[0]}",
                source_detectors=detectors,
                detection_count=1,
            )
        else:
            # Lower priority for non-flagged domains
            return FilteredIndicator(
                value=domain,
                indicator_type="domain",
                priority=IndicatorPriority.LOW,
                reason="Domain from traffic",
            )
    
    def _apply_limits(self, results: list[FilteredIndicator]) -> list[FilteredIndicator]:
        """Apply query limits by priority level."""
        limited = []
        counts = {
            IndicatorPriority.CRITICAL: 0,
            IndicatorPriority.HIGH: 0,
            IndicatorPriority.MEDIUM: 0,
            IndicatorPriority.LOW: 0,
        }
        
        # CRITICAL has no limit (all get included)
        # HIGH limited to max_high
        # MEDIUM limited to max_medium
        # LOW limited to max_low
        
        for indicator in results:
            if indicator.priority == IndicatorPriority.CRITICAL:
                limited.append(indicator)
                counts[IndicatorPriority.CRITICAL] += 1
            elif indicator.priority == IndicatorPriority.HIGH:
                if counts[IndicatorPriority.HIGH] < self.max_high:
                    limited.append(indicator)
                    counts[IndicatorPriority.HIGH] += 1
            elif indicator.priority == IndicatorPriority.MEDIUM:
                if counts[IndicatorPriority.MEDIUM] < self.max_medium:
                    limited.append(indicator)
                    counts[IndicatorPriority.MEDIUM] += 1
            elif indicator.priority == IndicatorPriority.LOW:
                if counts[IndicatorPriority.LOW] < self.max_low:
                    limited.append(indicator)
                    counts[IndicatorPriority.LOW] += 1
        
        logger.debug(
            "indicator_limits_applied",
            critical=counts[IndicatorPriority.CRITICAL],
            high=counts[IndicatorPriority.HIGH],
            medium=counts[IndicatorPriority.MEDIUM],
            low=counts[IndicatorPriority.LOW],
        )
        
        return limited
