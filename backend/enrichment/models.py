"""
NetSpecter Enrichment Data Models

Defines data structures for threat intelligence enrichment results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ThreatLevel(Enum):
    """Threat severity classification."""
    
    MALICIOUS = "malicious"  # Known malicious
    SUSPICIOUS = "suspicious"  # Some indicators, needs investigation
    UNKNOWN = "unknown"  # No data available
    CLEAN = "clean"  # Known benign


@dataclass
class VirusTotalResult:
    """
    VirusTotal API response data.
    
    Contains detection counts and categorization from VirusTotal's
    multi-vendor scanning results.
    """
    
    indicator: str
    indicator_type: str  # "ip" or "domain"
    
    # Detection stats
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    total_engines: int = 0
    
    # Categories and tags
    categories: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    
    # Network info (for IPs)
    country: str | None = None
    asn: int | None = None
    as_owner: str | None = None
    
    # Domain info
    registrar: str | None = None
    creation_date: str | None = None
    
    # Raw response timestamp
    last_analysis_date: datetime | None = None
    
    # Error state
    error: str | None = None
    
    @property
    def detection_ratio(self) -> str:
        """Get detection ratio string like '12/90'."""
        total = self.malicious_count + self.suspicious_count + self.harmless_count + self.undetected_count
        if total == 0:
            total = self.total_engines
        return f"{self.malicious_count}/{total}"
    
    @property
    def threat_level(self) -> ThreatLevel:
        """Classify threat level based on detection counts."""
        if self.error:
            return ThreatLevel.UNKNOWN
        
        if self.malicious_count >= 5:
            return ThreatLevel.MALICIOUS
        elif self.malicious_count >= 1 or self.suspicious_count >= 3:
            return ThreatLevel.SUSPICIOUS
        elif self.total_engines > 0 and self.malicious_count == 0:
            return ThreatLevel.CLEAN
        return ThreatLevel.UNKNOWN
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "source": "virustotal",
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "detection_ratio": self.detection_ratio,
            "malicious_count": self.malicious_count,
            "suspicious_count": self.suspicious_count,
            "total_engines": self.total_engines,
            "categories": self.categories,
            "tags": self.tags,
            "country": self.country,
            "asn": self.asn,
            "as_owner": self.as_owner,
            "threat_level": self.threat_level.value,
            "error": self.error,
        }


@dataclass
class AbuseIPDBResult:
    """
    AbuseIPDB API response data.
    
    Contains abuse confidence score and report details.
    """
    
    ip_address: str
    
    # Abuse metrics
    abuse_confidence_score: int = 0  # 0-100
    total_reports: int = 0
    distinct_users: int = 0
    
    # Classification
    is_whitelisted: bool = False
    is_tor_node: bool = False
    
    # Network info
    country_code: str | None = None
    isp: str | None = None
    domain: str | None = None
    usage_type: str | None = None  # "ISP", "Data Center", etc.
    
    # Report categories (numeric codes)
    categories: list[int] = field(default_factory=list)
    
    # Last reported date
    last_reported_at: str | None = None
    
    # Error state
    error: str | None = None
    
    # AbuseIPDB category mapping
    CATEGORY_NAMES = {
        1: "DNS Compromise",
        2: "DNS Poisoning",
        3: "Fraud Orders",
        4: "DDoS Attack",
        5: "FTP Brute-Force",
        6: "Ping of Death",
        7: "Phishing",
        8: "Fraud VoIP",
        9: "Open Proxy",
        10: "Web Spam",
        11: "Email Spam",
        12: "Blog Spam",
        13: "VPN IP",
        14: "Port Scan",
        15: "Hacking",
        16: "SQL Injection",
        17: "Spoofing",
        18: "Brute-Force",
        19: "Bad Web Bot",
        20: "Exploited Host",
        21: "Web App Attack",
        22: "SSH",
        23: "IoT Targeted",
    }
    
    @property
    def category_names(self) -> list[str]:
        """Convert category codes to human-readable names."""
        return [
            self.CATEGORY_NAMES.get(cat, f"Category-{cat}")
            for cat in self.categories
        ]
    
    @property
    def threat_level(self) -> ThreatLevel:
        """Classify threat level based on abuse score."""
        if self.error:
            return ThreatLevel.UNKNOWN
        
        if self.is_whitelisted:
            return ThreatLevel.CLEAN
        if self.abuse_confidence_score >= 75:
            return ThreatLevel.MALICIOUS
        elif self.abuse_confidence_score >= 25:
            return ThreatLevel.SUSPICIOUS
        elif self.total_reports == 0:
            return ThreatLevel.CLEAN
        return ThreatLevel.UNKNOWN
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "source": "abuseipdb",
            "ip_address": self.ip_address,
            "abuse_confidence_score": self.abuse_confidence_score,
            "total_reports": self.total_reports,
            "distinct_users": self.distinct_users,
            "is_tor_node": self.is_tor_node,
            "country_code": self.country_code,
            "isp": self.isp,
            "usage_type": self.usage_type,
            "categories": self.category_names,
            "last_reported_at": self.last_reported_at,
            "threat_level": self.threat_level.value,
            "error": self.error,
        }


@dataclass
class OTXResult:
    """
    AlienVault OTX API response data.
    
    Contains pulse information and threat indicators.
    """
    
    indicator: str
    indicator_type: str  # "IPv4", "domain", "hostname"
    
    # Pulse stats
    pulse_count: int = 0
    pulses: list[dict] = field(default_factory=list)  # List of pulse summaries
    
    # Threat tags
    tags: list[str] = field(default_factory=list)
    
    # Geo info
    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    
    # Network info
    asn: str | None = None
    
    # Validation
    validation: list[dict] = field(default_factory=list)
    
    # Malware families
    malware_families: list[str] = field(default_factory=list)
    
    # Error state
    error: str | None = None
    
    @property
    def threat_level(self) -> ThreatLevel:
        """Classify threat level based on pulse count and content."""
        if self.error:
            return ThreatLevel.UNKNOWN
        
        if self.pulse_count >= 3 or self.malware_families:
            return ThreatLevel.MALICIOUS
        elif self.pulse_count >= 1:
            return ThreatLevel.SUSPICIOUS
        return ThreatLevel.UNKNOWN
    
    @property
    def pulse_names(self) -> list[str]:
        """Get list of pulse names/titles."""
        return [p.get("name", "Unknown Pulse") for p in self.pulses[:5]]
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "source": "otx",
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "pulse_count": self.pulse_count,
            "pulse_names": self.pulse_names,
            "tags": self.tags,
            "malware_families": self.malware_families,
            "country_code": self.country_code,
            "asn": self.asn,
            "threat_level": self.threat_level.value,
            "error": self.error,
        }


@dataclass
class EnrichmentResult:
    """
    Aggregated enrichment result for an indicator.
    
    Combines results from all threat intelligence sources.
    """
    
    indicator: str
    indicator_type: str  # "ip" or "domain"
    
    # Individual source results
    virustotal: VirusTotalResult | None = None
    abuseipdb: AbuseIPDBResult | None = None
    otx: OTXResult | None = None
    
    # Aggregated assessment
    cached: bool = False
    enriched_at: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def overall_threat_level(self) -> ThreatLevel:
        """
        Determine overall threat level from all sources.
        
        Takes the most severe classification across all sources.
        """
        levels = []
        
        if self.virustotal:
            levels.append(self.virustotal.threat_level)
        if self.abuseipdb:
            levels.append(self.abuseipdb.threat_level)
        if self.otx:
            levels.append(self.otx.threat_level)
        
        if not levels:
            return ThreatLevel.UNKNOWN
        
        # Priority: MALICIOUS > SUSPICIOUS > UNKNOWN > CLEAN
        if ThreatLevel.MALICIOUS in levels:
            return ThreatLevel.MALICIOUS
        if ThreatLevel.SUSPICIOUS in levels:
            return ThreatLevel.SUSPICIOUS
        if ThreatLevel.CLEAN in levels:
            return ThreatLevel.CLEAN
        return ThreatLevel.UNKNOWN
    
    @property
    def source_count(self) -> int:
        """Count of sources that returned data."""
        count = 0
        if self.virustotal and not self.virustotal.error:
            count += 1
        if self.abuseipdb and not self.abuseipdb.error:
            count += 1
        if self.otx and not self.otx.error:
            count += 1
        return count
    
    @property
    def summary(self) -> str:
        """Generate a brief summary of findings."""
        parts = []
        
        if self.virustotal and self.virustotal.malicious_count > 0:
            parts.append(f"VT: {self.virustotal.detection_ratio} detections")
        
        if self.abuseipdb and self.abuseipdb.abuse_confidence_score > 0:
            parts.append(f"AbuseIPDB: {self.abuseipdb.abuse_confidence_score}% confidence")
        
        if self.otx and self.otx.pulse_count > 0:
            parts.append(f"OTX: {self.otx.pulse_count} pulses")
        
        if not parts:
            return "No threat indicators found"
        
        return " | ".join(parts)
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "overall_threat_level": self.overall_threat_level.value,
            "summary": self.summary,
            "source_count": self.source_count,
            "cached": self.cached,
            "enriched_at": self.enriched_at.isoformat(),
            "sources": {
                "virustotal": self.virustotal.to_dict() if self.virustotal else None,
                "abuseipdb": self.abuseipdb.to_dict() if self.abuseipdb else None,
                "otx": self.otx.to_dict() if self.otx else None,
            },
        }
