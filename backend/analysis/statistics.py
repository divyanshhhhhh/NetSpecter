"""
NetSpecter Statistical Analysis Engine

Comprehensive traffic statistics extraction from parsed PCAP data.
Includes protocol distribution, top talkers, timeline analysis, and entropy calculation.
"""

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

from backend.analysis.models import (
    ApplicationProtocol,
    Conversation,
    DNSQuery,
    Flow,
    ParseResult,
    Protocol,
    TLSInfo,
)

logger = structlog.get_logger(__name__)


# =============================================================================
# Statistics Data Models
# =============================================================================


@dataclass
class ProtocolStats:
    """Protocol distribution statistics."""

    transport_protocols: dict[str, int] = field(default_factory=dict)
    """Packet counts by transport protocol (TCP, UDP, ICMP)."""

    transport_percentages: dict[str, float] = field(default_factory=dict)
    """Percentage of total packets by transport protocol."""

    app_protocols: dict[str, int] = field(default_factory=dict)
    """Packet counts by application protocol (HTTP, HTTPS, DNS, etc)."""

    app_percentages: dict[str, float] = field(default_factory=dict)
    """Percentage of total packets by application protocol."""


@dataclass
class TopTalker:
    """Represents a top talking IP or port."""

    identifier: str
    """IP address or port number."""

    packet_count: int
    """Total packets."""

    byte_count: int = 0
    """Total bytes (if available)."""

    percentage: float = 0.0
    """Percentage of total traffic."""

    is_private: bool = False
    """Whether this is a private/internal IP."""


@dataclass
class TimelineBucket:
    """Traffic statistics for a time interval."""

    timestamp: float
    """Start of the bucket (Unix timestamp)."""

    packet_count: int = 0
    """Packets in this interval."""

    byte_count: int = 0
    """Bytes in this interval."""

    inbound_bytes: int = 0
    """Inbound traffic bytes."""

    outbound_bytes: int = 0
    """Outbound traffic bytes."""

    unique_ips: set[str] = field(default_factory=set)
    """Unique IPs active in this interval."""


@dataclass
class DNSStats:
    """DNS traffic statistics."""

    total_queries: int = 0
    """Total DNS queries."""

    unique_domains: int = 0
    """Number of unique domains queried."""

    query_types: dict[str, int] = field(default_factory=dict)
    """Distribution of query types (A, AAAA, TXT, etc)."""

    top_queried_domains: list[tuple[str, int]] = field(default_factory=list)
    """Most frequently queried domains."""

    suspicious_tld_queries: list[DNSQuery] = field(default_factory=list)
    """Queries to suspicious TLDs (.tk, .xyz, etc)."""

    high_entropy_subdomains: list[DNSQuery] = field(default_factory=list)
    """Domains with high-entropy subdomains (potential tunneling)."""

    long_subdomains: list[DNSQuery] = field(default_factory=list)
    """Domains with unusually long subdomains."""


@dataclass
class TLSStats:
    """TLS/SSL statistics."""

    total_connections: int = 0
    """Total TLS connections observed."""

    unique_snis: int = 0
    """Number of unique SNI values."""

    versions: dict[str, int] = field(default_factory=dict)
    """TLS version distribution."""

    self_signed_certs: list[TLSInfo] = field(default_factory=list)
    """Self-signed certificates detected."""

    expired_certs: list[TLSInfo] = field(default_factory=list)
    """Expired certificates detected."""

    top_snis: list[tuple[str, int]] = field(default_factory=list)
    """Most common SNI values."""


@dataclass
class AnomalyIndicator:
    """An anomaly detected during statistical analysis."""

    category: str
    """Type of anomaly (beacon, entropy, volume, etc)."""

    severity: str
    """Severity level (low, medium, high, critical)."""

    description: str
    """Human-readable description."""

    affected_ips: list[str] = field(default_factory=list)
    """IPs involved in this anomaly."""

    indicators: dict[str, Any] = field(default_factory=dict)
    """Additional data specific to this anomaly type."""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "affected_ips": self.affected_ips,
            "indicators": self.indicators,
        }


@dataclass
class TrafficStatistics:
    """Complete traffic statistics from PCAP analysis."""

    # Overview
    total_packets: int = 0
    total_bytes: int = 0
    duration_seconds: float = 0.0
    start_time: float = 0.0
    end_time: float = 0.0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0

    # IP statistics
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_external_ips: int = 0
    unique_internal_ips: int = 0

    # Protocol breakdown
    protocol_stats: ProtocolStats = field(default_factory=ProtocolStats)

    # Top talkers
    top_src_ips: list[TopTalker] = field(default_factory=list)
    top_dst_ips: list[TopTalker] = field(default_factory=list)
    top_dst_ports: list[TopTalker] = field(default_factory=list)
    top_conversations: list[dict] = field(default_factory=list)

    # Timeline
    timeline_buckets: list[TimelineBucket] = field(default_factory=list)
    bucket_interval_seconds: int = 60

    # DNS analysis
    dns_stats: DNSStats = field(default_factory=DNSStats)

    # TLS analysis
    tls_stats: TLSStats = field(default_factory=TLSStats)

    # Flow analysis
    total_flows: int = 0
    long_duration_flows: list[dict] = field(default_factory=list)
    high_volume_flows: list[dict] = field(default_factory=list)
    syn_only_flows: list[dict] = field(default_factory=list)

    # Anomalies
    anomalies: list[AnomalyIndicator] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "overview": {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "duration_seconds": self.duration_seconds,
                "start_time": self.start_time,
                "end_time": self.end_time,
                "packets_per_second": round(self.packets_per_second, 2),
                "bytes_per_second": round(self.bytes_per_second, 2),
            },
            "ip_stats": {
                "unique_src_ips": self.unique_src_ips,
                "unique_dst_ips": self.unique_dst_ips,
                "unique_external_ips": self.unique_external_ips,
                "unique_internal_ips": self.unique_internal_ips,
            },
            "protocols": {
                "transport": self.protocol_stats.transport_protocols,
                "transport_pct": {
                    k: round(v, 2) for k, v in self.protocol_stats.transport_percentages.items()
                },
                "application": self.protocol_stats.app_protocols,
                "application_pct": {
                    k: round(v, 2) for k, v in self.protocol_stats.app_percentages.items()
                },
            },
            "top_talkers": {
                "src_ips": [
                    {
                        "ip": t.identifier,
                        "packets": t.packet_count,
                        "bytes": t.byte_count,
                        "pct": round(t.percentage, 2),
                        "is_private": t.is_private,
                    }
                    for t in self.top_src_ips
                ],
                "dst_ips": [
                    {
                        "ip": t.identifier,
                        "packets": t.packet_count,
                        "bytes": t.byte_count,
                        "pct": round(t.percentage, 2),
                        "is_private": t.is_private,
                    }
                    for t in self.top_dst_ips
                ],
                "dst_ports": [
                    {
                        "port": t.identifier,
                        "packets": t.packet_count,
                        "pct": round(t.percentage, 2),
                    }
                    for t in self.top_dst_ports
                ],
            },
            "top_conversations": self.top_conversations,
            "dns": {
                "total_queries": self.dns_stats.total_queries,
                "unique_domains": self.dns_stats.unique_domains,
                "query_types": self.dns_stats.query_types,
                "top_domains": self.dns_stats.top_queried_domains[:20],
                "suspicious_tld_count": len(self.dns_stats.suspicious_tld_queries),
                "high_entropy_count": len(self.dns_stats.high_entropy_subdomains),
            },
            "tls": {
                "total_connections": self.tls_stats.total_connections,
                "unique_snis": self.tls_stats.unique_snis,
                "versions": self.tls_stats.versions,
                "self_signed_count": len(self.tls_stats.self_signed_certs),
                "expired_count": len(self.tls_stats.expired_certs),
                "top_snis": self.tls_stats.top_snis[:20],
            },
            "flows": {
                "total": self.total_flows,
                "long_duration_count": len(self.long_duration_flows),
                "high_volume_count": len(self.high_volume_flows),
                "syn_only_count": len(self.syn_only_flows),
            },
            "anomalies": [
                {
                    "category": a.category,
                    "severity": a.severity,
                    "description": a.description,
                    "affected_ips": a.affected_ips,
                    "indicators": a.indicators,
                }
                for a in self.anomalies
            ],
        }


# =============================================================================
# Statistics Engine
# =============================================================================


class StatisticsEngine:
    """
    Engine for extracting comprehensive statistics from parsed PCAP data.
    """

    def __init__(self, parse_result: ParseResult):
        """
        Initialize with parsed PCAP data.

        Args:
            parse_result: Result from PCAP parser
        """
        self.parse_result = parse_result
        self.stats = TrafficStatistics()

    def analyze(self) -> TrafficStatistics:
        """
        Run complete statistical analysis.

        Returns:
            TrafficStatistics with all computed metrics
        """
        logger.info("statistics_analysis_starting")

        # Basic overview
        self._compute_overview()

        # Protocol distribution
        self._compute_protocol_stats()

        # Top talkers
        self._compute_top_talkers()

        # Timeline
        self._compute_timeline()

        # DNS analysis
        self._analyze_dns()

        # TLS analysis
        self._analyze_tls()

        # Flow analysis
        self._analyze_flows()

        # Detect anomalies
        self._detect_anomalies()

        logger.info(
            "statistics_analysis_complete",
            anomalies=len(self.stats.anomalies),
        )

        return self.stats

    def _compute_overview(self) -> None:
        """Compute basic traffic overview statistics."""
        pr = self.parse_result

        self.stats.total_packets = pr.total_packets
        self.stats.total_bytes = pr.total_bytes
        self.stats.start_time = pr.start_time
        self.stats.end_time = pr.end_time
        self.stats.duration_seconds = pr.duration_seconds

        if pr.duration_seconds > 0:
            self.stats.packets_per_second = pr.total_packets / pr.duration_seconds
            self.stats.bytes_per_second = pr.total_bytes / pr.duration_seconds

        # IP counts
        self.stats.unique_src_ips = len(pr.src_ip_counts)
        self.stats.unique_dst_ips = len(pr.dst_ip_counts)

        # Count internal vs external
        all_ips = set(pr.src_ip_counts.keys()) | set(pr.dst_ip_counts.keys())
        for ip in all_ips:
            if _is_private_ip(ip):
                self.stats.unique_internal_ips += 1
            else:
                self.stats.unique_external_ips += 1

    def _compute_protocol_stats(self) -> None:
        """Compute protocol distribution statistics."""
        pr = self.parse_result
        total = max(1, pr.total_packets)

        # Transport protocols
        self.stats.protocol_stats.transport_protocols = dict(pr.protocol_counts)
        self.stats.protocol_stats.transport_percentages = {
            proto: (count / total) * 100
            for proto, count in pr.protocol_counts.items()
        }

        # Application protocols
        self.stats.protocol_stats.app_protocols = dict(pr.app_protocol_counts)
        self.stats.protocol_stats.app_percentages = {
            proto: (count / total) * 100
            for proto, count in pr.app_protocol_counts.items()
        }

    def _compute_top_talkers(self, top_n: int = 20) -> None:
        """Compute top talking IPs and ports."""
        pr = self.parse_result
        total_packets = max(1, pr.total_packets)

        # Top source IPs
        src_ip_sorted = sorted(
            pr.src_ip_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:top_n]

        self.stats.top_src_ips = [
            TopTalker(
                identifier=ip,
                packet_count=count,
                percentage=(count / total_packets) * 100,
                is_private=_is_private_ip(ip),
            )
            for ip, count in src_ip_sorted
        ]

        # Top destination IPs
        dst_ip_sorted = sorted(
            pr.dst_ip_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:top_n]

        self.stats.top_dst_ips = [
            TopTalker(
                identifier=ip,
                packet_count=count,
                percentage=(count / total_packets) * 100,
                is_private=_is_private_ip(ip),
            )
            for ip, count in dst_ip_sorted
        ]

        # Top destination ports
        port_sorted = sorted(
            pr.dst_port_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:top_n]

        self.stats.top_dst_ports = [
            TopTalker(
                identifier=str(port),
                packet_count=count,
                percentage=(count / total_packets) * 100,
            )
            for port, count in port_sorted
        ]

        # Top conversations by bytes
        conv_sorted = sorted(
            pr.conversations.values(),
            key=lambda c: c.total_bytes,
            reverse=True,
        )[:top_n]

        self.stats.top_conversations = [
            {
                "ip_a": c.ip_a,
                "ip_b": c.ip_b,
                "packets": c.total_packets,
                "bytes": c.total_bytes,
                "duration": round(c.duration_seconds, 2),
                "byte_ratio": round(c.byte_ratio, 2) if c.byte_ratio != float("inf") else "inf",
            }
            for c in conv_sorted
        ]

    def _compute_timeline(self, bucket_seconds: int = 60) -> None:
        """Compute traffic timeline in buckets."""
        pr = self.parse_result
        self.stats.bucket_interval_seconds = bucket_seconds

        if pr.start_time == 0 or pr.duration_seconds == 0:
            return

        # Create buckets
        buckets: dict[int, TimelineBucket] = {}

        for flow in pr.flows.values():
            # Distribute flow packets across time buckets
            if flow.timestamps:
                for ts in flow.timestamps:
                    bucket_idx = int((ts - pr.start_time) // bucket_seconds)
                    if bucket_idx not in buckets:
                        buckets[bucket_idx] = TimelineBucket(
                            timestamp=pr.start_time + (bucket_idx * bucket_seconds)
                        )

                    bucket = buckets[bucket_idx]
                    bucket.packet_count += 1
                    bucket.unique_ips.add(flow.src_ip)
                    bucket.unique_ips.add(flow.dst_ip)

                    # Estimate bytes per packet
                    if flow.packet_count > 0:
                        avg_bytes = flow.byte_count / flow.packet_count
                        bucket.byte_count += int(avg_bytes)

                        # Track direction
                        if _is_private_ip(flow.src_ip) and not _is_private_ip(flow.dst_ip):
                            bucket.outbound_bytes += int(avg_bytes)
                        elif not _is_private_ip(flow.src_ip) and _is_private_ip(flow.dst_ip):
                            bucket.inbound_bytes += int(avg_bytes)

        # Sort by timestamp
        self.stats.timeline_buckets = sorted(
            buckets.values(),
            key=lambda b: b.timestamp,
        )

    def _analyze_dns(self) -> None:
        """Analyze DNS traffic for anomalies."""
        dns_queries = self.parse_result.dns_queries

        if not dns_queries:
            return

        self.stats.dns_stats.total_queries = len(dns_queries)

        # Count domains and query types
        domain_counts: Counter[str] = Counter()
        parent_domain_counts: Counter[str] = Counter()
        query_type_counts: Counter[str] = Counter()

        suspicious_tlds = {".tk", ".xyz", ".top", ".pw", ".cc", ".icu", ".buzz", ".ml", ".ga", ".cf"}

        for query in dns_queries:
            domain_counts[query.query_name] += 1
            parent_domain_counts[query.parent_domain] += 1
            query_type_counts[query.query_type] += 1

            # Check for suspicious TLDs
            if any(query.query_name.lower().endswith(tld) for tld in suspicious_tlds):
                self.stats.dns_stats.suspicious_tld_queries.append(query)

            # Check for high-entropy subdomains (potential tunneling)
            if query.subdomain and len(query.subdomain) > 10:
                entropy = _calculate_entropy(query.subdomain)
                if entropy > 3.5:  # High entropy threshold
                    self.stats.dns_stats.high_entropy_subdomains.append(query)

            # Check for unusually long subdomains
            if query.subdomain_length > 50:
                self.stats.dns_stats.long_subdomains.append(query)

        self.stats.dns_stats.unique_domains = len(domain_counts)
        self.stats.dns_stats.query_types = dict(query_type_counts)
        self.stats.dns_stats.top_queried_domains = parent_domain_counts.most_common(50)

    def _analyze_tls(self) -> None:
        """Analyze TLS traffic."""
        tls_info = self.parse_result.tls_info

        if not tls_info:
            return

        self.stats.tls_stats.total_connections = len(tls_info)

        sni_counts: Counter[str] = Counter()
        version_counts: Counter[str] = Counter()

        for tls in tls_info:
            if tls.sni:
                sni_counts[tls.sni] += 1
            if tls.version:
                version_counts[tls.version] += 1
            if tls.is_self_signed:
                self.stats.tls_stats.self_signed_certs.append(tls)
            if tls.is_expired:
                self.stats.tls_stats.expired_certs.append(tls)

        self.stats.tls_stats.unique_snis = len(sni_counts)
        self.stats.tls_stats.versions = dict(version_counts)
        self.stats.tls_stats.top_snis = sni_counts.most_common(50)

    def _analyze_flows(self) -> None:
        """Analyze flow patterns."""
        flows = self.parse_result.flows

        self.stats.total_flows = len(flows)

        for flow in flows.values():
            # Long duration flows (> 1 hour)
            if flow.duration_seconds > 3600:
                self.stats.long_duration_flows.append({
                    "src": f"{flow.src_ip}:{flow.src_port}",
                    "dst": f"{flow.dst_ip}:{flow.dst_port}",
                    "protocol": flow.protocol.value,
                    "duration_hours": round(flow.duration_seconds / 3600, 2),
                    "packets": flow.packet_count,
                    "bytes": flow.byte_count,
                })

            # High volume flows (> 10MB)
            if flow.byte_count > 10 * 1024 * 1024:
                self.stats.high_volume_flows.append({
                    "src": f"{flow.src_ip}:{flow.src_port}",
                    "dst": f"{flow.dst_ip}:{flow.dst_port}",
                    "protocol": flow.protocol.value,
                    "bytes_mb": round(flow.byte_count / (1024 * 1024), 2),
                    "packets": flow.packet_count,
                })

            # SYN-only flows (potential scans)
            if flow.is_syn_only and flow.packet_count < 5:
                self.stats.syn_only_flows.append({
                    "src": flow.src_ip,
                    "dst": f"{flow.dst_ip}:{flow.dst_port}",
                    "packets": flow.packet_count,
                })

    def _detect_anomalies(self) -> None:
        """Detect statistical anomalies in the traffic."""
        # 1. Beacon detection (regular intervals)
        self._detect_beacons()

        # 2. Large data transfers
        self._detect_large_transfers()

        # 3. Suspicious DNS patterns
        self._detect_dns_anomalies()

        # 4. Port scan patterns
        self._detect_port_scans()

        # 5. Traffic spikes
        self._detect_traffic_spikes()

    def _detect_beacons(self) -> None:
        """Detect potential C2 beacons based on regular intervals."""
        for flow in self.parse_result.flows.values():
            if len(flow.timestamps) < 10:
                continue

            # Skip internal-only traffic
            if _is_private_ip(flow.src_ip) and _is_private_ip(flow.dst_ip):
                continue

            # Calculate inter-arrival times
            intervals = []
            sorted_ts = sorted(flow.timestamps)
            for i in range(1, len(sorted_ts)):
                intervals.append(sorted_ts[i] - sorted_ts[i - 1])

            if len(intervals) < 5:
                continue

            # Calculate jitter (standard deviation)
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval < 5:  # Skip very frequent connections
                continue

            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)

            # Low jitter = potential beacon
            jitter_pct = (std_dev / mean_interval) * 100 if mean_interval > 0 else 100

            if jitter_pct < 15 and len(intervals) >= 10:  # Very regular
                self.stats.anomalies.append(
                    AnomalyIndicator(
                        category="beacon",
                        severity="high" if jitter_pct < 5 else "medium",
                        description=f"Regular connection interval detected (~{mean_interval:.0f}s, jitter {jitter_pct:.1f}%)",
                        affected_ips=[flow.src_ip, flow.dst_ip],
                        indicators={
                            "mean_interval_seconds": round(mean_interval, 2),
                            "jitter_percent": round(jitter_pct, 2),
                            "connection_count": len(flow.timestamps),
                            "flow": flow.flow_key,
                        },
                    )
                )

    def _detect_large_transfers(self) -> None:
        """Detect unusually large data transfers."""
        for conv in self.parse_result.conversations.values():
            # Large outbound transfer to external IP
            if not _is_private_ip(conv.ip_a) or not _is_private_ip(conv.ip_b):
                external_ip = conv.ip_a if not _is_private_ip(conv.ip_a) else conv.ip_b
                internal_ip = conv.ip_b if not _is_private_ip(conv.ip_a) else conv.ip_a

                # Check for asymmetric traffic (potential exfiltration)
                if conv.byte_ratio > 10 and conv.total_bytes > 5 * 1024 * 1024:
                    outbound = conv.bytes_a_to_b if conv.ip_a == internal_ip else conv.bytes_b_to_a

                    self.stats.anomalies.append(
                        AnomalyIndicator(
                            category="exfiltration",
                            severity="high" if outbound > 50 * 1024 * 1024 else "medium",
                            description=f"Large asymmetric transfer: {_format_bytes(outbound)} outbound (ratio {conv.byte_ratio:.1f}:1)",
                            affected_ips=[internal_ip, external_ip],
                            indicators={
                                "outbound_bytes": outbound,
                                "ratio": round(conv.byte_ratio, 2),
                                "external_ip": external_ip,
                            },
                        )
                    )

    def _detect_dns_anomalies(self) -> None:
        """Detect DNS-based anomalies."""
        # High entropy subdomains (potential DNS tunneling)
        if len(self.stats.dns_stats.high_entropy_subdomains) > 5:
            domains = set(q.parent_domain for q in self.stats.dns_stats.high_entropy_subdomains)
            for domain in list(domains)[:5]:  # Top 5 suspicious domains
                queries = [q for q in self.stats.dns_stats.high_entropy_subdomains if q.parent_domain == domain]
                self.stats.anomalies.append(
                    AnomalyIndicator(
                        category="dns_tunnel",
                        severity="high",
                        description=f"High-entropy subdomains to {domain} ({len(queries)} queries)",
                        affected_ips=list(set(q.src_ip for q in queries)),
                        indicators={
                            "domain": domain,
                            "query_count": len(queries),
                            "sample_queries": [q.query_name for q in queries[:5]],
                        },
                    )
                )

        # Suspicious TLD usage
        if self.stats.dns_stats.suspicious_tld_queries:
            tld_counts: Counter[str] = Counter()
            for q in self.stats.dns_stats.suspicious_tld_queries:
                parts = q.query_name.split(".")
                if parts:
                    tld_counts[f".{parts[-1]}"] += 1

            for tld, count in tld_counts.most_common(3):
                if count > 3:
                    self.stats.anomalies.append(
                        AnomalyIndicator(
                            category="suspicious_dns",
                            severity="medium",
                            description=f"{count} queries to suspicious TLD {tld}",
                            affected_ips=list(set(
                                q.src_ip for q in self.stats.dns_stats.suspicious_tld_queries
                                if q.query_name.endswith(tld)
                            )),
                            indicators={
                                "tld": tld,
                                "count": count,
                            },
                        )
                    )

    def _detect_port_scans(self) -> None:
        """Detect port scanning patterns."""
        # Group SYN-only flows by source IP
        src_scan_targets: dict[str, set[str]] = defaultdict(set)

        for flow_info in self.stats.syn_only_flows:
            src_ip = flow_info["src"]
            dst = flow_info["dst"]
            src_scan_targets[src_ip].add(dst)

        # Flag IPs that attempted many connections
        for src_ip, targets in src_scan_targets.items():
            if len(targets) >= 10:
                # Check for port scan vs host scan
                unique_ports = set(t.split(":")[-1] for t in targets if ":" in t)
                unique_hosts = set(t.split(":")[0] for t in targets if ":" in t)

                if len(unique_ports) > len(unique_hosts) * 2:
                    scan_type = "vertical (port scan)"
                elif len(unique_hosts) > len(unique_ports) * 2:
                    scan_type = "horizontal (host scan)"
                else:
                    scan_type = "mixed"

                self.stats.anomalies.append(
                    AnomalyIndicator(
                        category="port_scan",
                        severity="medium",
                        description=f"{scan_type.capitalize()} detected: {len(targets)} targets",
                        affected_ips=[src_ip],
                        indicators={
                            "scan_type": scan_type,
                            "target_count": len(targets),
                            "unique_ports": len(unique_ports),
                            "unique_hosts": len(unique_hosts),
                            "sample_targets": list(targets)[:10],
                        },
                    )
                )

    def _detect_traffic_spikes(self) -> None:
        """Detect unusual traffic spikes."""
        buckets = self.stats.timeline_buckets

        if len(buckets) < 10:
            return

        # Calculate average traffic
        avg_packets = sum(b.packet_count for b in buckets) / len(buckets)
        avg_bytes = sum(b.byte_count for b in buckets) / len(buckets)

        if avg_packets == 0:
            return

        # Find spikes (> 3x average)
        for bucket in buckets:
            if bucket.packet_count > avg_packets * 3 and bucket.packet_count > 100:
                self.stats.anomalies.append(
                    AnomalyIndicator(
                        category="traffic_spike",
                        severity="low",
                        description=f"Traffic spike: {bucket.packet_count} packets ({bucket.packet_count/avg_packets:.1f}x average)",
                        affected_ips=list(bucket.unique_ips)[:10],
                        indicators={
                            "timestamp": bucket.timestamp,
                            "packets": bucket.packet_count,
                            "bytes": bucket.byte_count,
                            "multiplier": round(bucket.packet_count / avg_packets, 2),
                        },
                    )
                )


# =============================================================================
# Helper Functions
# =============================================================================


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/internal."""
    if not ip:
        return False

    if ip == "::1":
        return True

    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False

        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        if parts[0] == 169 and parts[1] == 254:
            return True

        return False
    except (ValueError, IndexError):
        return False


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
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


def _format_bytes(bytes_count: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if bytes_count < 1024:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024
    return f"{bytes_count:.1f} TB"


# =============================================================================
# Main Function
# =============================================================================


def compute_statistics(parse_result: ParseResult) -> TrafficStatistics:
    """
    Compute comprehensive statistics from parsed PCAP data.

    Args:
        parse_result: Result from PCAP parser

    Returns:
        TrafficStatistics with all computed metrics
    """
    engine = StatisticsEngine(parse_result)
    return engine.analyze()
