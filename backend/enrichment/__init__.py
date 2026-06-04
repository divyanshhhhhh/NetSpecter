"""
NetSpecter Threat Intelligence Enrichment

Provides external threat intelligence lookups from:
- VirusTotal (IP/domain reputation)
- AbuseIPDB (IP abuse reports)
- AlienVault OTX (threat intelligence pulses)
"""

from backend.enrichment.cache import EnrichmentCache
from backend.enrichment.filter import IndicatorFilter, IndicatorPriority
from backend.enrichment.manager import EnrichmentManager
from backend.enrichment.models import (
    EnrichmentResult,
    VirusTotalResult,
    AbuseIPDBResult,
    OTXResult,
    ThreatLevel,
)

__all__ = [
    "EnrichmentCache",
    "IndicatorFilter",
    "IndicatorPriority",
    "EnrichmentManager",
    "EnrichmentResult",
    "VirusTotalResult",
    "AbuseIPDBResult",
    "OTXResult",
    "ThreatLevel",
]
