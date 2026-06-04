"""
NetSpecter Context Builder

Formats analysis data into structured prompts for LLM consumption.
Manages context limits and prioritizes important information.
"""

from datetime import datetime
from typing import Any

from backend.analysis.statistics import TrafficStatistics, AnomalyIndicator


# =============================================================================
# Context Size Limits
# =============================================================================

# Maximum characters for different sections
MAX_OVERVIEW_CHARS = 2000
MAX_PROTOCOL_CHARS = 1000
MAX_TOP_TALKERS_CHARS = 3000
MAX_DNS_CHARS = 2000
MAX_TLS_CHARS = 1000
MAX_ANOMALIES_CHARS = 4000
MAX_FLOWS_CHARS = 2000


# =============================================================================
# Context Builder
# =============================================================================


class ContextBuilder:
    """
    Builds formatted context for LLM prompts from analysis data.

    Manages token limits by prioritizing important information
    and truncating less critical details.
    """

    def __init__(self, stats: TrafficStatistics):
        """
        Initialize with traffic statistics.

        Args:
            stats: Computed traffic statistics
        """
        self.stats = stats

    def build_stats_summary(self, max_chars: int = 12000) -> str:
        """
        Build a comprehensive statistics summary for LLM analysis.

        Args:
            max_chars: Maximum characters in output

        Returns:
            Formatted statistics summary
        """
        sections = []

        # Overview section
        sections.append(self._build_overview())

        # Protocol distribution
        sections.append(self._build_protocol_section())

        # Top talkers
        sections.append(self._build_top_talkers_section())

        # Conversations
        sections.append(self._build_conversations_section())

        # DNS analysis
        if self.stats.dns_stats.total_queries > 0:
            sections.append(self._build_dns_section())

        # TLS analysis
        if self.stats.tls_stats.total_connections > 0:
            sections.append(self._build_tls_section())

        # Flow analysis
        sections.append(self._build_flow_section())

        # Detected anomalies
        if self.stats.anomalies:
            sections.append(self._build_anomalies_section())

        # Combine and truncate if needed
        result = "\n\n".join(sections)

        if len(result) > max_chars:
            # Truncate with indicator
            result = result[: max_chars - 50] + "\n\n[... truncated for length ...]"

        return result

    def build_anomalies_summary(self) -> str:
        """
        Build a focused summary of detected anomalies.

        Returns:
            Formatted anomalies summary
        """
        if not self.stats.anomalies:
            return "No anomalies detected during statistical analysis."

        lines = ["## Detected Anomalies", ""]

        # Group by severity
        by_severity: dict[str, list[AnomalyIndicator]] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
        }

        for anomaly in self.stats.anomalies:
            severity = anomaly.severity.lower()
            if severity in by_severity:
                by_severity[severity].append(anomaly)

        # Output by severity
        for severity in ["critical", "high", "medium", "low"]:
            anomalies = by_severity[severity]
            if not anomalies:
                continue

            lines.append(f"### {severity.upper()} Severity")
            lines.append("")

            for i, anomaly in enumerate(anomalies, 1):
                lines.append(f"**{i}. {anomaly.category.replace('_', ' ').title()}**")
                lines.append(f"- Description: {anomaly.description}")
                if anomaly.affected_ips:
                    lines.append(f"- Affected IPs: {', '.join(anomaly.affected_ips[:5])}")
                if anomaly.indicators:
                    # Format key indicators
                    key_indicators = []
                    for k, v in list(anomaly.indicators.items())[:3]:
                        if isinstance(v, (list, dict)):
                            continue
                        key_indicators.append(f"{k}: {v}")
                    if key_indicators:
                        lines.append(f"- Indicators: {', '.join(key_indicators)}")
                lines.append("")

        return "\n".join(lines)

    def _build_overview(self) -> str:
        """Build traffic overview section."""
        s = self.stats

        # Format duration
        duration = s.duration_seconds
        if duration > 3600:
            duration_str = f"{duration / 3600:.1f} hours"
        elif duration > 60:
            duration_str = f"{duration / 60:.1f} minutes"
        else:
            duration_str = f"{duration:.0f} seconds"

        # Format times
        start_str = datetime.fromtimestamp(s.start_time).strftime("%Y-%m-%d %H:%M:%S") if s.start_time else "N/A"
        end_str = datetime.fromtimestamp(s.end_time).strftime("%Y-%m-%d %H:%M:%S") if s.end_time else "N/A"

        return f"""## Traffic Overview

- **Capture Duration**: {duration_str}
- **Time Range**: {start_str} to {end_str}
- **Total Packets**: {s.total_packets:,}
- **Total Bytes**: {_format_bytes(s.total_bytes)}
- **Packets/Second**: {s.packets_per_second:.1f}
- **Bytes/Second**: {_format_bytes(int(s.bytes_per_second))}/s

### IP Statistics
- Unique Source IPs: {s.unique_src_ips:,}
- Unique Destination IPs: {s.unique_dst_ips:,}
- Internal IPs: {s.unique_internal_ips:,}
- External IPs: {s.unique_external_ips:,}"""

    def _build_protocol_section(self) -> str:
        """Build protocol distribution section."""
        ps = self.stats.protocol_stats

        lines = ["## Protocol Distribution", "", "### Transport Layer"]

        for proto, count in sorted(ps.transport_protocols.items(), key=lambda x: -x[1]):
            pct = ps.transport_percentages.get(proto, 0)
            lines.append(f"- {proto}: {count:,} packets ({pct:.1f}%)")

        lines.append("")
        lines.append("### Application Layer")

        # Filter out UNKNOWN if there are others
        app_protos = {k: v for k, v in ps.app_protocols.items() if k != "UNKNOWN" or len(ps.app_protocols) == 1}

        for proto, count in sorted(app_protos.items(), key=lambda x: -x[1])[:10]:
            pct = ps.app_percentages.get(proto, 0)
            lines.append(f"- {proto}: {count:,} packets ({pct:.1f}%)")

        return "\n".join(lines)

    def _build_top_talkers_section(self) -> str:
        """Build top talkers section."""
        lines = ["## Top Talkers", "", "### Top Source IPs"]

        for i, talker in enumerate(self.stats.top_src_ips[:10], 1):
            internal = " (internal)" if talker.is_private else " (external)"
            lines.append(
                f"{i}. {talker.identifier}{internal}: {talker.packet_count:,} packets ({talker.percentage:.1f}%)"
            )

        lines.append("")
        lines.append("### Top Destination IPs")

        for i, talker in enumerate(self.stats.top_dst_ips[:10], 1):
            internal = " (internal)" if talker.is_private else " (external)"
            lines.append(
                f"{i}. {talker.identifier}{internal}: {talker.packet_count:,} packets ({talker.percentage:.1f}%)"
            )

        lines.append("")
        lines.append("### Top Destination Ports")

        for i, talker in enumerate(self.stats.top_dst_ports[:10], 1):
            port_name = _get_port_name(int(talker.identifier))
            lines.append(
                f"{i}. Port {talker.identifier} ({port_name}): {talker.packet_count:,} packets ({talker.percentage:.1f}%)"
            )

        return "\n".join(lines)

    def _build_conversations_section(self) -> str:
        """Build top conversations section."""
        lines = ["## Top Conversations (by volume)", ""]

        for i, conv in enumerate(self.stats.top_conversations[:10], 1):
            ratio_str = f"{conv['byte_ratio']}:1" if conv["byte_ratio"] != "inf" else "outbound only"
            lines.append(
                f"{i}. {conv['ip_a']} ↔ {conv['ip_b']}: "
                f"{_format_bytes(conv['bytes'])}, {conv['packets']:,} packets, "
                f"ratio {ratio_str}"
            )

        return "\n".join(lines)

    def _build_dns_section(self) -> str:
        """Build DNS analysis section."""
        dns = self.stats.dns_stats

        lines = [
            "## DNS Analysis",
            "",
            f"- Total Queries: {dns.total_queries:,}",
            f"- Unique Domains: {dns.unique_domains:,}",
            "",
            "### Query Type Distribution",
        ]

        for qtype, count in sorted(dns.query_types.items(), key=lambda x: -x[1])[:8]:
            lines.append(f"- {qtype}: {count:,}")

        lines.append("")
        lines.append("### Top Queried Domains")

        for domain, count in dns.top_queried_domains[:15]:
            lines.append(f"- {domain}: {count:,} queries")

        # Suspicious findings
        if dns.suspicious_tld_queries:
            lines.append("")
            lines.append("### ⚠️ Suspicious TLD Queries")
            unique_domains = set(q.query_name for q in dns.suspicious_tld_queries)
            for domain in list(unique_domains)[:10]:
                lines.append(f"- {domain}")

        if dns.high_entropy_subdomains:
            lines.append("")
            lines.append("### ⚠️ High-Entropy Subdomains (Potential Tunneling)")
            unique_domains = set(q.parent_domain for q in dns.high_entropy_subdomains)
            for domain in list(unique_domains)[:5]:
                count = sum(1 for q in dns.high_entropy_subdomains if q.parent_domain == domain)
                lines.append(f"- {domain}: {count} suspicious queries")

        return "\n".join(lines)

    def _build_tls_section(self) -> str:
        """Build TLS analysis section."""
        tls = self.stats.tls_stats

        lines = [
            "## TLS/SSL Analysis",
            "",
            f"- Total TLS Connections: {tls.total_connections:,}",
            f"- Unique SNI Values: {tls.unique_snis:,}",
        ]

        if tls.versions:
            lines.append("")
            lines.append("### TLS Versions")
            for version, count in sorted(tls.versions.items(), key=lambda x: -x[1]):
                lines.append(f"- {version}: {count:,}")

        if tls.top_snis:
            lines.append("")
            lines.append("### Top SNI Values")
            for sni, count in tls.top_snis[:10]:
                lines.append(f"- {sni}: {count:,}")

        if tls.self_signed_certs:
            lines.append("")
            lines.append(f"### ⚠️ Self-Signed Certificates: {len(tls.self_signed_certs)}")

        if tls.expired_certs:
            lines.append("")
            lines.append(f"### ⚠️ Expired Certificates: {len(tls.expired_certs)}")

        return "\n".join(lines)

    def _build_flow_section(self) -> str:
        """Build flow analysis section."""
        lines = [
            "## Flow Analysis",
            "",
            f"- Total Flows: {self.stats.total_flows:,}",
        ]

        if self.stats.long_duration_flows:
            lines.append(f"- Long Duration Flows (>1hr): {len(self.stats.long_duration_flows)}")

        if self.stats.high_volume_flows:
            lines.append(f"- High Volume Flows (>10MB): {len(self.stats.high_volume_flows)}")

        if self.stats.syn_only_flows:
            lines.append(f"- SYN-Only Flows (potential scans): {len(self.stats.syn_only_flows)}")

        # Show some high volume flows
        if self.stats.high_volume_flows:
            lines.append("")
            lines.append("### High Volume Flows")
            for flow in self.stats.high_volume_flows[:5]:
                lines.append(
                    f"- {flow['src']} → {flow['dst']}: {flow['bytes_mb']} MB"
                )

        return "\n".join(lines)

    def _build_anomalies_section(self) -> str:
        """Build detected anomalies section."""
        return self.build_anomalies_summary()


# =============================================================================
# Helper Functions
# =============================================================================


def _format_bytes(bytes_count: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if bytes_count < 1024:
            return f"{bytes_count:.1f} {unit}"
        bytes_count = bytes_count / 1024
    return f"{bytes_count:.1f} TB"


def _get_port_name(port: int) -> str:
    """Get common name for well-known ports."""
    port_names = {
        20: "FTP-Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1434: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
    }
    return port_names.get(port, "Unknown")


def build_context(stats: TrafficStatistics, max_chars: int = 12000) -> str:
    """
    Build LLM context from traffic statistics.

    Args:
        stats: Computed traffic statistics
        max_chars: Maximum characters in output

    Returns:
        Formatted context string
    """
    builder = ContextBuilder(stats)
    return builder.build_stats_summary(max_chars)
