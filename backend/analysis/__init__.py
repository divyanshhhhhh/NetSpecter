"""
NetSpecter Analysis Module

Core analysis components including parser, models, and detectors.
"""

from backend.analysis.models import (
    Conversation,
    DNSQuery,
    Flow,
    PacketSummary,
    ParseResult,
    ParserProgress,
    TLSInfo,
)
from backend.analysis.parser import parse_pcap, stream_packets
from backend.analysis.statistics import (
    compute_statistics,
    StatisticsEngine,
    TrafficStatistics,
)

__all__ = [
    "PacketSummary",
    "Flow",
    "Conversation",
    "DNSQuery",
    "TLSInfo",
    "ParseResult",
    "ParserProgress",
    "parse_pcap",
    "stream_packets",
    "compute_statistics",
    "StatisticsEngine",
    "TrafficStatistics",
]
