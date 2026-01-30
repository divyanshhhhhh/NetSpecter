"""
NetSpecter Smart Indicator Filter

Filters indicators for enrichment based on traffic analysis:
1. Analyze top 40% of conversations by volume
2. Extract public IPs that communicate with top private IPs
3. Extract domains related to those conversations
4. Filter against legitimate domains list
5. Detect typosquatting attempts
"""

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Path to legitimate domains file
LEGIT_DOMAINS_FILE = Path(__file__).parent / "legitdomains.txt"

# Top percentage of conversations to analyze
TOP_CONVERSATIONS_PERCENT = 0.40  # 40%

# Common typosquatting character substitutions
TYPOSQUAT_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s",
    "!": "i",
    "|": "l",
    "rn": "m",  # Common visual trick
    "vv": "w",  # Common visual trick
}

# High-value brand domains to check for typosquatting
BRAND_DOMAINS = {
    "google", "microsoft", "apple", "amazon", "facebook", "twitter",
    "instagram", "linkedin", "paypal", "netflix", "spotify", "dropbox",
    "github", "gitlab", "adobe", "oracle", "salesforce", "zoom",
    "slack", "discord", "whatsapp", "telegram", "signal",
}


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class ConversationStats:
    """Statistics for a conversation (flow between two IPs)."""
    
    src_ip: str
    dst_ip: str
    packet_count: int = 0
    byte_count: int = 0
    protocol: str = ""
    domains: set[str] = field(default_factory=set)
    
    @property
    def is_src_private(self) -> bool:
        """Check if source IP is private."""
        try:
            return ipaddress.ip_address(self.src_ip).is_private
        except ValueError:
            return False
    
    @property
    def is_dst_private(self) -> bool:
        """Check if destination IP is private."""
        try:
            return ipaddress.ip_address(self.dst_ip).is_private
        except ValueError:
            return False
    
    @property
    def has_public_endpoint(self) -> bool:
        """Check if this conversation involves a public IP."""
        return not self.is_src_private or not self.is_dst_private
    
    @property
    def public_ip(self) -> str | None:
        """Get the public IP in this conversation, if any."""
        if not self.is_src_private:
            return self.src_ip
        if not self.is_dst_private:
            return self.dst_ip
        return None


@dataclass
class FilteredIndicators:
    """Result of smart indicator filtering."""
    
    public_ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    typosquat_suspects: set[str] = field(default_factory=set)
    
    # Stats for logging
    total_conversations: int = 0
    top_conversations_analyzed: int = 0
    domains_filtered_by_legit: int = 0
    
    def total_indicators(self) -> int:
        """Total number of indicators to check."""
        return len(self.public_ips) + len(self.domains)


# =============================================================================
# Legitimate Domain Checker
# =============================================================================


class LegitDomainChecker:
    """
    Checks domains against legitimate domain list and detects typosquatting.
    """
    
    def __init__(self, legit_file: Path | None = None):
        """
        Initialize with legitimate domains file.
        
        Args:
            legit_file: Path to legitimate domains file (uses default if not provided)
        """
        self.legit_file = legit_file or LEGIT_DOMAINS_FILE
        self.legit_domains: set[str] = set()
        self._load_legit_domains()
    
    def _load_legit_domains(self) -> None:
        """Load legitimate domains from file."""
        if not self.legit_file.exists():
            logger.warning("legit_domains_file_not_found", path=str(self.legit_file))
            return
        
        try:
            with open(self.legit_file, "r") as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith("#"):
                        continue
                    # Store lowercase domain
                    self.legit_domains.add(line.lower())
            
            logger.info("legit_domains_loaded", count=len(self.legit_domains))
        except Exception as e:
            logger.error("legit_domains_load_error", error=str(e))
    
    def is_legit(self, domain: str) -> bool:
        """
        Check if domain is in legitimate list.
        
        Args:
            domain: Domain to check
        
        Returns:
            True if domain or its parent is in legitimate list
        """
        domain = domain.lower().strip(".")
        
        # Check exact match
        if domain in self.legit_domains:
            return True
        
        # Check parent domains
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self.legit_domains:
                return True
        
        return False
    
    def normalize_typosquat(self, domain: str) -> str:
        """
        Normalize a domain by replacing typosquatting characters.
        
        Args:
            domain: Domain to normalize
        
        Returns:
            Normalized domain string
        """
        normalized = domain.lower()
        
        # Apply character substitutions
        for fake, real in TYPOSQUAT_SUBSTITUTIONS.items():
            normalized = normalized.replace(fake, real)
        
        return normalized
    
    def detect_typosquat(self, domain: str) -> str | None:
        """
        Detect if domain is a typosquatting attempt of a brand domain.
        
        Args:
            domain: Domain to check
        
        Returns:
            The brand being spoofed, or None if not typosquatting
        """
        domain_lower = domain.lower().strip(".")
        normalized = self.normalize_typosquat(domain_lower)
        
        # Extract the main domain name (without TLD)
        parts = domain_lower.split(".")
        if len(parts) < 2:
            return None
        
        main_name = parts[-2] if len(parts) >= 2 else parts[0]
        normalized_name = self.normalize_typosquat(main_name)
        
        # Check against brand domains
        for brand in BRAND_DOMAINS:
            # Skip if it's an exact match (legitimate)
            if main_name == brand:
                return None
            
            # Check if normalized version matches brand
            if normalized_name == brand:
                return brand
            
            # Check Levenshtein distance for close matches
            if self._is_similar(main_name, brand, max_distance=2):
                return brand
            
            # Check if brand appears in normalized domain
            if brand in normalized and brand not in domain_lower:
                return brand
        
        return None
    
    def _is_similar(self, s1: str, s2: str, max_distance: int = 2) -> bool:
        """
        Check if two strings are similar using Levenshtein distance.
        
        Args:
            s1: First string
            s2: Second string
            max_distance: Maximum allowed edit distance
        
        Returns:
            True if strings are within max_distance edits
        """
        # Skip if length difference is too large
        if abs(len(s1) - len(s2)) > max_distance:
            return False
        
        # Simple Levenshtein distance calculation
        if len(s1) < len(s2):
            s1, s2 = s2, s1
        
        distances = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            new_distances = [i + 1]
            for j, c2 in enumerate(s2):
                if c1 == c2:
                    new_distances.append(distances[j])
                else:
                    new_distances.append(1 + min(
                        distances[j],
                        distances[j + 1],
                        new_distances[-1]
                    ))
            distances = new_distances
        
        return distances[-1] <= max_distance


# =============================================================================
# Smart Indicator Filter
# =============================================================================


class SmartIndicatorFilter:
    """
    Filters indicators based on traffic analysis.
    
    Strategy:
    1. Analyze all conversations (flows) and rank by volume
    2. Take top 40% most active conversations
    3. From those, identify public IPs communicating with private IPs
    4. Extract domains related to those conversations
    5. Filter out legitimate domains
    6. Flag typosquatting attempts
    """
    
    def __init__(self, legit_checker: LegitDomainChecker | None = None):
        """Initialize the filter."""
        self.legit_checker = legit_checker or LegitDomainChecker()
    
    def filter_indicators(
        self,
        flows: dict[str, Any],
        dns_queries: list[Any],
        tls_info: list[Any],
        top_percent: float = TOP_CONVERSATIONS_PERCENT,
        use_top: bool = True,
    ) -> FilteredIndicators:
        """
        Filter indicators based on traffic statistics.
        
        Args:
            flows: Dictionary of flow objects from parser
            dns_queries: List of DNS query objects
            tls_info: List of TLS info objects
            top_percent: Percentage of conversations to analyze (default 40%)
            use_top: If True, analyze top N% by volume; if False, analyze bottom N%
        
        Returns:
            FilteredIndicators with public IPs and domains to check
        """
        result = FilteredIndicators()
        result.total_conversations = len(flows)
        
        # Build conversation stats
        conversations: list[ConversationStats] = []
        
        for flow_key, flow in flows.items():
            conv = ConversationStats(
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                packet_count=flow.packet_count,
                byte_count=flow.byte_count,
            )
            conversations.append(conv)
        
        if not conversations:
            logger.warning("no_conversations_found")
            return result
        
        # Sort by byte count (most traffic first if use_top=True, else least first)
        conversations.sort(key=lambda c: c.byte_count, reverse=use_top)
        
        # Take specified percentage
        selected_count = max(1, int(len(conversations) * top_percent))
        selected_conversations = conversations[:selected_count]
        result.top_conversations_analyzed = len(selected_conversations)
        
        direction = "top" if use_top else "bottom"
        logger.info(
            f"{direction}_conversations_selected",
            total=len(conversations),
            selected=selected_count,
            percent=top_percent * 100,
        )
        
        # Collect public IPs from top conversations
        top_private_ips: set[str] = set()
        
        for conv in selected_conversations:
            if conv.has_public_endpoint:
                public_ip = conv.public_ip
                if public_ip:
                    result.public_ips.add(public_ip)
                
                # Track which private IPs are talking to public IPs
                if conv.is_src_private:
                    top_private_ips.add(conv.src_ip)
                if conv.is_dst_private:
                    top_private_ips.add(conv.dst_ip)
        
        logger.info(
            "public_ips_identified",
            count=len(result.public_ips),
            top_private_ips=len(top_private_ips),
        )
        
        # Build IP-to-domain mapping from DNS queries
        ip_to_domains: dict[str, set[str]] = {}
        domain_to_ips: dict[str, set[str]] = {}
        
        for query in dns_queries:
            domain = query.query_name
            if not domain:
                continue
            
            # Get resolved IPs from answers
            for answer in getattr(query, "answers", []):
                if answer and not answer.startswith(("CNAME", "SOA", "NS")):
                    # This looks like an IP answer
                    ip_to_domains.setdefault(answer, set()).add(domain)
                    domain_to_ips.setdefault(domain, set()).add(answer)
        
        # Also get domains from TLS SNI
        for tls in tls_info:
            if tls.sni:
                # Associate SNI domain with the server IP
                server_ip = getattr(tls, "server_ip", None)
                if server_ip:
                    ip_to_domains.setdefault(server_ip, set()).add(tls.sni)
                    domain_to_ips.setdefault(tls.sni, set()).add(server_ip)
        
        # Get domains related to our public IPs
        related_domains: set[str] = set()
        for ip in result.public_ips:
            if ip in ip_to_domains:
                related_domains.update(ip_to_domains[ip])
        
        # Also add domains whose resolved IPs match our public IPs
        for domain, ips in domain_to_ips.items():
            if ips & result.public_ips:
                related_domains.add(domain)
        
        logger.info(
            "related_domains_found",
            count=len(related_domains),
        )
        
        # Filter domains
        for domain in related_domains:
            domain = domain.lower().strip(".")
            
            # Skip empty or local domains
            if not domain or domain.endswith((".local", ".lan", ".internal", ".arpa")):
                continue
            
            # Check for typosquatting first
            spoofed_brand = self.legit_checker.detect_typosquat(domain)
            if spoofed_brand:
                result.typosquat_suspects.add(domain)
                result.domains.add(domain)  # Include typosquats for enrichment
                logger.warning(
                    "typosquat_detected",
                    domain=domain,
                    spoofed_brand=spoofed_brand,
                )
                continue
            
            # Check against legitimate domains
            if self.legit_checker.is_legit(domain):
                result.domains_filtered_by_legit += 1
                continue
            
            # Add to domains to enrich
            result.domains.add(domain)
        
        logger.info(
            "indicator_filtering_complete",
            public_ips=len(result.public_ips),
            domains=len(result.domains),
            typosquats=len(result.typosquat_suspects),
            filtered_legit=result.domains_filtered_by_legit,
        )
        
        return result


# =============================================================================
# Singleton Instances
# =============================================================================

_legit_checker: LegitDomainChecker | None = None
_smart_filter: SmartIndicatorFilter | None = None


def get_legit_checker() -> LegitDomainChecker:
    """Get the singleton legitimate domain checker."""
    global _legit_checker
    if _legit_checker is None:
        _legit_checker = LegitDomainChecker()
    return _legit_checker


def get_smart_filter() -> SmartIndicatorFilter:
    """Get the singleton smart indicator filter."""
    global _smart_filter
    if _smart_filter is None:
        _smart_filter = SmartIndicatorFilter()
    return _smart_filter
