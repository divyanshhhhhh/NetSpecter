"""
NetSpecter Report Generator

Generates comprehensive markdown reports from analysis results.
"""

from datetime import datetime
from pathlib import Path
from typing import Any


# =============================================================================
# Report Generator
# =============================================================================


class ReportGenerator:
    """Generates markdown analysis reports."""
    
    def __init__(self):
        """Initialize the generator."""
        pass
    
    def generate(
        self,
        pcap_name: str,
        results: dict[str, Any],
    ) -> str:
        """
        Generate a complete markdown report.
        
        Args:
            pcap_name: Name of the analyzed PCAP file
            results: Complete analysis results dictionary
        
        Returns:
            Markdown formatted report string
        """
        sections = []
        
        # Header
        sections.append(self._generate_header(pcap_name))
        
        # Executive Summary
        sections.append(self._generate_executive_summary(results))
        
        # Traffic Statistics
        if results.get("statistics"):
            sections.append(self._generate_statistics(results["statistics"]))
        
        # Detection Findings
        if results.get("detections"):
            sections.append(self._generate_detections(results["detections"]))
        
        # Threat Intelligence
        if results.get("enrichment"):
            sections.append(self._generate_enrichment(results["enrichment"]))
        
        # AI Analysis
        if results.get("synthesis"):
            sections.append(self._generate_synthesis(results["synthesis"]))
        
        # Wireshark Filters
        if results.get("wireshark_filters"):
            sections.append(self._generate_filters(results["wireshark_filters"]))
        
        # Footer
        sections.append(self._generate_footer())
        
        return "\n\n".join(sections)
    
    def _generate_header(self, pcap_name: str) -> str:
        """Generate report header."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return f"""# NetSpecter Analysis Report

**File:** `{pcap_name}`  
**Generated:** {timestamp}  
**Tool:** NetSpecter v0.1.0

---"""
    
    def _generate_executive_summary(self, results: dict) -> str:
        """Generate executive summary section."""
        summary = results.get("summary", {})
        synthesis = results.get("synthesis", {})
        
        threat_level = summary.get("threat_level", "unknown").upper()
        threat_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🔴",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "NONE": "🟢",
            "UNKNOWN": "⚪",
        }.get(threat_level, "⚪")
        
        lines = [
            "## Executive Summary",
            "",
            f"**Threat Level:** {threat_emoji} **{threat_level}**",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Packets | {summary.get('total_packets', 0):,} |",
            f"| Total Bytes | {self._format_bytes(summary.get('total_bytes', 0))} |",
            f"| Duration | {self._format_duration(summary.get('duration_seconds', 0))} |",
            f"| Detections | {summary.get('detections', 0)} |",
            f"| Malicious Indicators | {summary.get('malicious_indicators', 0)} |",
            f"| Wireshark Filters | {len(summary.get('wireshark_filters', []))} |",
        ]
        
        # Add AI executive summary if available
        if synthesis.get("executive_summary"):
            lines.extend([
                "",
                "### AI Assessment",
                "",
                synthesis["executive_summary"],
            ])
        
        return "\n".join(lines)
    
    def _generate_statistics(self, stats: dict) -> str:
        """Generate statistics section."""
        lines = [
            "## Traffic Statistics",
            "",
        ]
        
        # Protocol distribution
        protocol_stats = stats.get("protocol_stats", {})
        transport = protocol_stats.get("transport_protocols", {})
        transport_pct = protocol_stats.get("transport_percentages", {})
        
        if transport:
            lines.extend([
                "### Protocol Distribution",
                "",
                "| Protocol | Packets | Percentage |",
                "|----------|---------|------------|",
            ])
            
            for proto, count in sorted(transport.items(), key=lambda x: x[1], reverse=True)[:10]:
                pct = transport_pct.get(proto, 0)
                lines.append(f"| {proto.upper()} | {count:,} | {pct:.1f}% |")
            
            lines.append("")
        
        # Top source IPs
        top_src = stats.get("top_src_ips", [])
        if top_src:
            lines.extend([
                "### Top Source IPs",
                "",
                "| IP Address | Packets | Bytes |",
                "|------------|---------|-------|",
            ])
            
            for item in top_src[:10]:
                ip = item.get("identifier", item.get("ip", ""))
                packets = item.get("packet_count", 0)
                bytes_count = item.get("byte_count", 0)
                lines.append(f"| `{ip}` | {packets:,} | {self._format_bytes(bytes_count)} |")
            
            lines.append("")
        
        # Top destination IPs
        top_dst = stats.get("top_dst_ips", [])
        if top_dst:
            lines.extend([
                "### Top Destination IPs",
                "",
                "| IP Address | Packets | Bytes |",
                "|------------|---------|-------|",
            ])
            
            for item in top_dst[:10]:
                ip = item.get("identifier", item.get("ip", ""))
                packets = item.get("packet_count", 0)
                bytes_count = item.get("byte_count", 0)
                lines.append(f"| `{ip}` | {packets:,} | {self._format_bytes(bytes_count)} |")
            
            lines.append("")
        
        return "\n".join(lines)
    
    def _generate_detections(self, detections: list) -> str:
        """Generate detections section."""
        if not detections:
            return "## Security Detections\n\n✅ No security threats detected by behavioral analysis."
        
        lines = [
            "## Security Detections",
            "",
            f"⚠️ **{len(detections)} finding(s) detected**",
            "",
        ]
        
        for i, finding in enumerate(detections, 1):
            severity = finding.get("severity", "medium").upper()
            severity_emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🔴",
                "MEDIUM": "🟡",
                "LOW": "🔵",
                "INFO": "ℹ️",
            }.get(severity, "⚪")
            
            lines.extend([
                f"### {i}. {finding.get('title', 'Unknown Finding')}",
                "",
                f"**Severity:** {severity_emoji} {severity}  ",
                f"**Detector:** {finding.get('detector', 'Unknown')}  ",
                f"**Confidence:** {finding.get('confidence', 0) * 100:.0f}%",
                "",
            ])
            
            if finding.get("description"):
                lines.extend([
                    finding["description"],
                    "",
                ])
            
            affected_ips = finding.get("affected_ips", [])
            if affected_ips:
                lines.extend([
                    "**Affected IPs:**",
                    "",
                ])
                for ip in affected_ips[:10]:
                    lines.append(f"- `{ip}`")
                lines.append("")
        
        return "\n".join(lines)
    
    def _generate_enrichment(self, enrichment: dict) -> str:
        """Generate enrichment section."""
        lines = [
            "## Threat Intelligence Enrichment",
            "",
        ]
        
        # Stats
        stats = enrichment.get("stats", {})
        if isinstance(stats, dict):
            # Handle new cascading stats format
            overall = stats.get("overall", stats)
            lines.extend([
                "### Enrichment Statistics",
                "",
                "| Source | Checked | Flagged |",
                "|--------|---------|---------|",
            ])
            
            if "otx" in stats:
                otx = stats["otx"]
                lines.append(f"| AlienVault OTX | {otx.get('checked', 0)} | {otx.get('flagged', 0)} |")
            if "abuseipdb" in stats:
                abuse = stats["abuseipdb"]
                lines.append(f"| AbuseIPDB | {abuse.get('checked', 0)} | {abuse.get('flagged', 0)} |")
            if "virustotal" in stats:
                vt = stats["virustotal"]
                lines.append(f"| VirusTotal | {vt.get('checked', 0)} | {vt.get('malicious', 0)} |")
            
            lines.append("")
        
        # Flagged indicators
        flagged = enrichment.get("flagged_indicators", [])
        if flagged:
            lines.extend([
                "### 🚨 Flagged Indicators",
                "",
                "| Indicator | Type | Threat Level | Sources |",
                "|-----------|------|--------------|---------|",
            ])
            
            for item in flagged[:20]:
                indicator = item.get("indicator", "")
                ind_type = item.get("indicator_type", "")
                threat_level = item.get("threat_level", "unknown")
                
                threat_emoji = "🔴" if threat_level == "malicious" else "🟡"
                sources = item.get("summary", "")
                
                # Add malware families if present
                families = item.get("malware_families", [])
                if families:
                    sources += f" ({', '.join(families)})"
                
                lines.append(f"| `{indicator}` | {ind_type} | {threat_emoji} {threat_level} | {sources} |")
            
            lines.append("")
        else:
            lines.append("✅ No malicious indicators found in threat intelligence databases.\n")
        
        return "\n".join(lines)
    
    def _generate_synthesis(self, synthesis: dict) -> str:
        """Generate AI synthesis section."""
        if not synthesis.get("success"):
            return ""
        
        lines = [
            "## AI Analysis",
            "",
        ]
        
        # Key findings
        key_findings = synthesis.get("key_findings", [])
        if key_findings:
            lines.extend([
                "### Key Findings",
                "",
            ])
            for finding in key_findings[:10]:
                lines.append(f"- {finding}")
            lines.append("")
        
        # Attack chains
        attack_chains = synthesis.get("attack_chains", [])
        if attack_chains:
            lines.extend([
                "### Attack Chains",
                "",
            ])
            for chain in attack_chains[:5]:
                if isinstance(chain, dict):
                    lines.append(f"- **{chain.get('name', 'Unknown')}**: {chain.get('description', '')}")
                else:
                    lines.append(f"- {chain}")
            lines.append("")
        
        # Recommendations
        recommendations = synthesis.get("recommendations", [])
        if recommendations:
            lines.extend([
                "### Recommendations",
                "",
            ])
            for rec in recommendations[:10]:
                lines.append(f"- {rec}")
            lines.append("")
        
        # IOCs
        iocs = synthesis.get("iocs", {})
        if iocs:
            lines.extend([
                "### Indicators of Compromise (IOCs)",
                "",
            ])
            for ioc_type, values in iocs.items():
                if values:
                    lines.append(f"**{ioc_type.upper()}:**")
                    for v in values[:10]:
                        lines.append(f"- `{v}`")
            lines.append("")
        
        return "\n".join(lines)
    
    def _generate_filters(self, filters: list) -> str:
        """Generate Wireshark filters section."""
        if not filters:
            return ""
        
        lines = [
            "## Wireshark Filters",
            "",
            "Copy these filters into Wireshark for manual investigation:",
            "",
        ]
        
        for i, f in enumerate(filters[:25], 1):
            name = f.get("name", f"Filter {i}")
            filter_text = f.get("filter_text", f.get("filter", ""))
            severity = f.get("severity", "medium")
            
            severity_emoji = {
                "critical": "🔴",
                "high": "🔴",
                "medium": "🟡",
                "low": "🔵",
            }.get(severity, "⚪")
            
            lines.extend([
                f"### {i}. {severity_emoji} {name}",
                "",
                "```",
                filter_text,
                "```",
                "",
            ])
            
            if f.get("description"):
                lines.append(f"_{f['description']}_\n")
        
        return "\n".join(lines)
    
    def _generate_footer(self) -> str:
        """Generate report footer."""
        return """---

*Generated by NetSpecter v0.1.0*  
*Author: Divyansh Pandya*  
*License: MIT*"""
    
    def _format_bytes(self, bytes_count: int) -> str:
        """Format bytes to human readable string."""
        if bytes_count < 1024:
            return f"{bytes_count} B"
        elif bytes_count < 1024 ** 2:
            return f"{bytes_count / 1024:.1f} KB"
        elif bytes_count < 1024 ** 3:
            return f"{bytes_count / (1024 ** 2):.1f} MB"
        else:
            return f"{bytes_count / (1024 ** 3):.2f} GB"
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration to human readable string."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            mins = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{mins}m {secs}s"
        else:
            hours = int(seconds // 3600)
            mins = int((seconds % 3600) // 60)
            return f"{hours}h {mins}m"


def save_report(
    report_content: str,
    pcap_path: Path,
) -> Path:
    """
    Save report to file.
    
    Args:
        report_content: Generated markdown content
        pcap_path: Path to the analyzed PCAP file
    
    Returns:
        Path to the saved report file
    """
    # Generate report filename
    report_name = f"{pcap_path.stem}_report.md"
    report_path = pcap_path.parent / report_name
    
    with open(report_path, "w") as f:
        f.write(report_content)
    
    return report_path


# =============================================================================
# Singleton Instance
# =============================================================================

_generator: ReportGenerator | None = None


def get_report_generator() -> ReportGenerator:
    """Get the singleton report generator."""
    global _generator
    if _generator is None:
        _generator = ReportGenerator()
    return _generator
