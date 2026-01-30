"""
NetSpecter DNS Tunneling Detector

Detects DNS-based data exfiltration and C2 communication by analyzing
subdomain entropy, query volume, and response characteristics.
"""

import math
import re
import string
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

from backend.analysis.detectors.base import BaseDetector, Finding, Severity
from backend.analysis.models import DNSQuery, ParseResult

logger = structlog.get_logger(__name__)


# Known legitimate high-entropy domains (CDNs, cloud services, etc.)
LEGITIMATE_HIGH_ENTROPY_DOMAINS = {
    "akamaiedge.net",
    "akamaihd.net",
    "cloudfront.net",
    "cloudflare.com",
    "fastly.net",
    "googleusercontent.com",
    "amazonaws.com",
    "azurewebsites.net",
    "blob.core.windows.net",
    "1e100.net",  # Google
}


@dataclass
class DomainAnalysis:
    """Analysis results for a parent domain."""

    domain: str
    queries: list[DNSQuery] = field(default_factory=list)
    unique_subdomains: set[str] = field(default_factory=set)
    total_query_count: int = 0
    txt_query_count: int = 0
    null_query_count: int = 0
    subdomain_entropies: list[float] = field(default_factory=list)
    avg_subdomain_length: float = 0.0
    max_subdomain_length: int = 0
    response_sizes: list[int] = field(default_factory=list)


class DNSTunnelDetector(BaseDetector):
    """
    Detects DNS tunneling for data exfiltration or C2.

    Detection signals include:
    - High entropy in subdomain names (Base32/Base64 encoding)
    - Excessive unique subdomains for a single parent domain
    - Unusual query types (TXT, NULL, CNAME chains)
    - Large DNS response sizes
    - High query volume to uncommon domains

    MITRE ATT&CK: T1071.004 (DNS), T1048.003 (Exfiltration Over DNS)
    """

    name = "dns_tunnel"
    description = "DNS tunneling and exfiltration detector"
    version = "1.0.0"

    DEFAULT_CONFIG = {
        # Minimum entropy to consider suspicious
        "min_suspicious_entropy": 3.5,
        # Minimum unique subdomains to analyze a domain
        "min_unique_subdomains": 5,
        # Threshold for high subdomain count
        "high_subdomain_threshold": 20,
        # Average subdomain length threshold
        "long_subdomain_threshold": 30,
        # Minimum queries to consider
        "min_queries": 3,
        # TXT query percentage threshold
        "txt_query_ratio_threshold": 0.3,
        # Known tunnel domains (common malware/pentest tools)
        "known_tunnel_patterns": [
            r".*\.dnscat\.",
            r".*\.dns2tcp\.",
            r".*\.iodine\.",
        ],
    }

    def _setup(self) -> None:
        """Initialize detector configuration."""
        for key, default in self.DEFAULT_CONFIG.items():
            if key not in self.config:
                self.config[key] = default

        # Compile regex patterns
        self._tunnel_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in self.config["known_tunnel_patterns"]
        ]

    def detect(self, parse_result: ParseResult) -> list[Finding]:
        """
        Analyze DNS queries for tunneling indicators.

        Args:
            parse_result: Parsed PCAP data with DNS queries.

        Returns:
            List of DNS tunnel detection findings.
        """
        findings = []

        if not parse_result.dns_queries:
            logger.debug("no_dns_queries_to_analyze")
            return findings

        # Group queries by parent domain
        domain_analyses = self._analyze_domains(parse_result.dns_queries)

        logger.debug(
            "dns_domains_analyzed",
            domain_count=len(domain_analyses),
        )

        for domain, analysis in domain_analyses.items():
            domain_findings = self._evaluate_domain(analysis)
            findings.extend(domain_findings)

        # Check for known tunnel tool patterns
        pattern_findings = self._check_known_patterns(parse_result.dns_queries)
        findings.extend(pattern_findings)

        logger.info(
            "dns_tunnel_detection_complete",
            findings_count=len(findings),
        )

        return findings

    def _analyze_domains(
        self, queries: list[DNSQuery]
    ) -> dict[str, DomainAnalysis]:
        """Group and analyze DNS queries by parent domain."""
        analyses: dict[str, DomainAnalysis] = {}

        for query in queries:
            # Extract parent domain (last 2 or 3 parts depending on TLD)
            parent = self._get_parent_domain(query.query_name)
            if not parent:
                continue

            if parent not in analyses:
                analyses[parent] = DomainAnalysis(domain=parent)

            analysis = analyses[parent]
            analysis.queries.append(query)
            analysis.total_query_count += 1

            # Extract subdomain
            subdomain = self._extract_subdomain(query.query_name, parent)
            if subdomain:
                analysis.unique_subdomains.add(subdomain)

                # Calculate entropy
                entropy = self._calculate_entropy(subdomain)
                analysis.subdomain_entropies.append(entropy)

                # Track length
                if len(subdomain) > analysis.max_subdomain_length:
                    analysis.max_subdomain_length = len(subdomain)

            # Track query types
            if query.query_type == "TXT":
                analysis.txt_query_count += 1
            elif query.query_type == "NULL":
                analysis.null_query_count += 1

            # Track response sizes
            if query.response_size > 0:
                analysis.response_sizes.append(query.response_size)

        # Calculate averages
        for analysis in analyses.values():
            if analysis.unique_subdomains:
                lengths = [len(s) for s in analysis.unique_subdomains]
                analysis.avg_subdomain_length = sum(lengths) / len(lengths)

        return analyses

    def _evaluate_domain(self, analysis: DomainAnalysis) -> list[Finding]:
        """Evaluate a domain for tunneling indicators."""
        findings = []

        # Skip if not enough data
        if analysis.total_query_count < self.config["min_queries"]:
            return findings

        # Skip known legitimate high-entropy domains
        if any(analysis.domain.endswith(d) for d in LEGITIMATE_HIGH_ENTROPY_DOMAINS):
            return findings

        # Calculate average entropy
        avg_entropy = (
            sum(analysis.subdomain_entropies) / len(analysis.subdomain_entropies)
            if analysis.subdomain_entropies
            else 0
        )

        # Scoring system for multiple indicators
        score = 0.0
        indicators: dict[str, Any] = {
            "domain": analysis.domain,
            "query_count": analysis.total_query_count,
            "unique_subdomains": len(analysis.unique_subdomains),
        }
        reasons = []

        # High entropy subdomains (Base32/Base64 encoded data)
        if avg_entropy >= self.config["min_suspicious_entropy"]:
            score += 0.3
            indicators["avg_entropy"] = round(avg_entropy, 3)
            reasons.append(f"High subdomain entropy ({avg_entropy:.2f} bits)")

        # Many unique subdomains (data chunking)
        if len(analysis.unique_subdomains) >= self.config["high_subdomain_threshold"]:
            score += 0.25
            reasons.append(f"Many unique subdomains ({len(analysis.unique_subdomains)})")

        # Long subdomains (more data per query)
        if analysis.avg_subdomain_length >= self.config["long_subdomain_threshold"]:
            score += 0.2
            indicators["avg_subdomain_length"] = round(analysis.avg_subdomain_length, 1)
            reasons.append(f"Long subdomains (avg {analysis.avg_subdomain_length:.0f} chars)")

        # TXT query ratio (often used for tunnel responses)
        txt_ratio = (
            analysis.txt_query_count / analysis.total_query_count
            if analysis.total_query_count > 0
            else 0
        )
        if txt_ratio >= self.config["txt_query_ratio_threshold"]:
            score += 0.15
            indicators["txt_query_ratio"] = round(txt_ratio, 3)
            reasons.append(f"High TXT query ratio ({txt_ratio:.1%})")

        # NULL queries (suspicious, rarely legitimate)
        if analysis.null_query_count > 0:
            score += 0.1
            indicators["null_query_count"] = analysis.null_query_count
            reasons.append(f"NULL query type used ({analysis.null_query_count} queries)")

        # Generate finding if score is high enough
        if score >= 0.35:  # At least 2-3 indicators
            confidence = min(1.0, score + 0.2)  # Boost for multiple indicators

            # Determine severity
            if score >= 0.7:
                severity = Severity.HIGH
            elif score >= 0.5:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            description = (
                f"Potential DNS tunneling detected to **{analysis.domain}**.\n\n"
                f"**Indicators:**\n"
            )
            for reason in reasons:
                description += f"- {reason}\n"

            description += (
                f"\n**Why this matters:** DNS tunneling encodes data in DNS queries "
                f"to bypass firewalls and DLP. High-entropy subdomains suggest "
                f"Base32/Base64 encoded payloads. Common tools include dnscat2, "
                f"iodine, and dns2tcp."
            )

            # Sample suspicious subdomains
            if analysis.unique_subdomains:
                sample = sorted(analysis.subdomain_entropies, reverse=True)[:3]
                indicators["sample_high_entropy_values"] = sample

            wireshark_filter = f'dns.qry.name contains "{analysis.domain}"'

            finding = self.create_finding(
                severity=severity,
                confidence=confidence,
                title=f"DNS Tunnel Suspected: {analysis.domain}",
                description=description,
                affected_ips=list(set(q.src_ip for q in analysis.queries if q.src_ip)),
                indicators=indicators,
                mitre_techniques=["T1071.004", "T1048.003"],
                wireshark_filter=wireshark_filter,
            )
            findings.append(finding)

        return findings

    def _check_known_patterns(self, queries: list[DNSQuery]) -> list[Finding]:
        """Check for known DNS tunnel tool patterns."""
        findings = []
        matched_tools: dict[str, list[str]] = defaultdict(list)

        for query in queries:
            for pattern in self._tunnel_patterns:
                if pattern.match(query.query_name):
                    # Extract tool name from pattern like r".*\.dnscat\."
                    # Split by \. to get tool name
                    parts = pattern.pattern.replace("\\.", "|").split("|")
                    tool = parts[1] if len(parts) > 1 else "unknown"
                    matched_tools[tool].append(query.query_name)

        for tool, domains in matched_tools.items():
            unique_domains = list(set(domains))[:5]  # Sample

            finding = self.create_finding(
                severity=Severity.CRITICAL,
                confidence=0.95,
                title=f"Known DNS Tunnel Tool Detected: {tool}",
                description=(
                    f"DNS queries match the signature of **{tool}**, a known DNS "
                    f"tunneling tool.\n\n"
                    f"**Sample queries:**\n"
                    + "\n".join(f"- `{d}`" for d in unique_domains)
                    + f"\n\n**Total matches:** {len(domains)}"
                ),
                indicators={
                    "tool": tool,
                    "match_count": len(domains),
                    "sample_queries": unique_domains,
                },
                mitre_techniques=["T1071.004", "T1048.003", "T1572"],
                wireshark_filter=f'dns.qry.name contains "{tool}"',
            )
            findings.append(finding)

        return findings

    @staticmethod
    def _get_parent_domain(fqdn: str) -> str | None:
        """Extract parent domain from FQDN."""
        if not fqdn:
            return None

        parts = fqdn.rstrip(".").lower().split(".")
        if len(parts) < 2:
            return None

        # Handle common 2-part TLDs
        if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "edu"):
            return ".".join(parts[-3:])

        return ".".join(parts[-2:])

    @staticmethod
    def _extract_subdomain(fqdn: str, parent: str) -> str | None:
        """Extract subdomain portion from FQDN."""
        if not fqdn or not parent:
            return None

        fqdn = fqdn.rstrip(".").lower()
        parent = parent.lower()

        if fqdn.endswith(parent):
            subdomain = fqdn[: -(len(parent) + 1)]  # Remove parent and dot
            return subdomain if subdomain else None

        return None

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0

        # Count character frequencies
        freq: dict[str, int] = {}
        for char in text.lower():
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy
