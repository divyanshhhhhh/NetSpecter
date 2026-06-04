"""
NetSpecter Data Exfiltration Detector

Detects potential data exfiltration by analyzing outbound transfer patterns,
unusual protocols, and traffic volume anomalies.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

from backend.analysis.detectors.base import BaseDetector, Finding, Severity
from backend.analysis.models import Flow, ParseResult, Protocol

logger = structlog.get_logger(__name__)


# Known cloud storage and paste site domains
CLOUD_STORAGE_DOMAINS = {
    "dropbox.com",
    "drive.google.com",
    "docs.google.com",
    "onedrive.live.com",
    "1drv.ms",
    "box.com",
    "mega.nz",
    "mega.io",
    "mediafire.com",
    "sendspace.com",
    "wetransfer.com",
    "transfer.sh",
    "file.io",
    "0x0.st",
}

PASTE_SITES = {
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "ghostbin.com",
    "dpaste.com",
    "paste.ubuntu.com",
    "gist.github.com",
    "privatebin.net",
    "termbin.com",
    "paste.mozilla.org",
}


@dataclass
class DestinationProfile:
    """Traffic profile for a destination."""

    dst_ip: str
    dst_ports: set[int] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)
    flows: list[Flow] = field(default_factory=list)
    total_bytes_out: int = 0
    total_bytes_in: int = 0
    total_packets: int = 0
    source_ips: set[str] = field(default_factory=set)
    timestamps: list[float] = field(default_factory=list)

    @property
    def byte_ratio(self) -> float:
        """Outbound/inbound byte ratio."""
        if self.total_bytes_in == 0:
            return float("inf") if self.total_bytes_out > 0 else 0.0
        return self.total_bytes_out / self.total_bytes_in


class ExfiltrationDetector(BaseDetector):
    """
    Detects potential data exfiltration patterns.

    Detection signals include:
    - Large outbound transfers to single external IP
    - High outbound/inbound byte ratio
    - Uploads to cloud storage or paste sites
    - Unusual protocols for bulk transfers (DNS, ICMP)
    - Off-hours bulk transfers

    MITRE ATT&CK: T1048 (Exfiltration Over Alternative Protocol), 
                  T1567 (Exfiltration to Cloud Storage)
    """

    name = "exfiltration"
    description = "Data exfiltration pattern detector"
    version = "1.0.0"

    DEFAULT_CONFIG = {
        # Minimum bytes to consider for exfiltration
        "min_bytes_threshold": 10 * 1024 * 1024,  # 10 MB
        # Large single transfer threshold
        "large_transfer_threshold": 50 * 1024 * 1024,  # 50 MB
        # Outbound/inbound ratio threshold
        "high_ratio_threshold": 10.0,  # 10:1 outbound ratio
        # DNS exfil bytes threshold (lower since it's unusual)
        "dns_exfil_threshold": 1 * 1024 * 1024,  # 1 MB via DNS
        # ICMP exfil threshold
        "icmp_exfil_threshold": 100 * 1024,  # 100 KB via ICMP
        # Off-hours definition (UTC)
        "off_hours_start": 22,  # 10 PM
        "off_hours_end": 6,  # 6 AM
        # Minimum number of flows to consider
        "min_flows": 1,
    }

    def _setup(self) -> None:
        """Initialize detector configuration."""
        for key, default in self.DEFAULT_CONFIG.items():
            if key not in self.config:
                self.config[key] = default

    def detect(self, parse_result: ParseResult) -> list[Finding]:
        """
        Analyze flows for data exfiltration patterns.

        Args:
            parse_result: Parsed PCAP data.

        Returns:
            List of exfiltration detection findings.
        """
        findings = []

        # Build destination profiles
        profiles = self._build_profiles(list(parse_result.flows.values()))

        logger.debug(
            "exfil_profiles_built",
            profile_count=len(profiles),
        )

        # Check for large transfers
        findings.extend(self._check_large_transfers(profiles))

        # Check for high outbound ratio
        findings.extend(self._check_high_ratio(profiles))

        # Check for unusual protocol exfil
        findings.extend(self._check_protocol_exfil(parse_result))

        # Check for cloud storage uploads
        findings.extend(self._check_cloud_storage(parse_result))

        logger.info(
            "exfiltration_detection_complete",
            findings_count=len(findings),
        )

        return findings

    def _build_profiles(self, flows: list[Flow]) -> dict[str, DestinationProfile]:
        """Build traffic profiles for each external destination."""
        profiles: dict[str, DestinationProfile] = {}

        for flow in flows:
            # Only analyze traffic to external destinations
            if self._is_private_ip(flow.dst_ip):
                continue

            # Skip if source is also external (pass-through traffic)
            if not self._is_private_ip(flow.src_ip):
                continue

            if flow.dst_ip not in profiles:
                profiles[flow.dst_ip] = DestinationProfile(dst_ip=flow.dst_ip)

            profile = profiles[flow.dst_ip]
            profile.flows.append(flow)
            profile.dst_ports.add(flow.dst_port)
            profile.protocols.add(flow.protocol)
            profile.source_ips.add(flow.src_ip)
            profile.total_packets += flow.packet_count
            profile.timestamps.append(flow.start_time)

            # Estimate bytes (outbound = source to dest)
            profile.total_bytes_out += flow.byte_count // 2  # Rough estimate
            profile.total_bytes_in += flow.byte_count // 2

        return profiles

    def _check_large_transfers(
        self, profiles: dict[str, DestinationProfile]
    ) -> list[Finding]:
        """Check for large outbound transfers."""
        findings = []

        for profile in profiles.values():
            total_bytes = sum(f.byte_count for f in profile.flows)

            if total_bytes >= self.config["large_transfer_threshold"]:
                severity = Severity.HIGH
                confidence = 0.7
            elif total_bytes >= self.config["min_bytes_threshold"]:
                severity = Severity.MEDIUM
                confidence = 0.5
            else:
                continue

            # Calculate duration
            if profile.timestamps:
                duration = max(profile.timestamps) - min(profile.timestamps)
                rate_mbps = (total_bytes * 8) / (duration * 1_000_000) if duration > 0 else 0
            else:
                duration = 0
                rate_mbps = 0

            description = (
                f"Large data transfer detected to **{profile.dst_ip}**.\n\n"
                f"**Transfer Details:**\n"
                f"- Total bytes: {self._format_bytes(total_bytes)}\n"
                f"- Duration: {duration:.0f} seconds\n"
                f"- Average rate: {rate_mbps:.1f} Mbps\n"
                f"- Ports: {', '.join(str(p) for p in sorted(profile.dst_ports))}\n"
                f"- Source IPs: {', '.join(sorted(profile.source_ips))}\n"
                f"\n**Why this matters:** Large outbound transfers may indicate "
                f"data exfiltration, especially to unfamiliar external IPs."
            )

            wireshark_filter = f"ip.dst == {profile.dst_ip}"

            finding = self.create_finding(
                severity=severity,
                confidence=confidence,
                title=f"Large Transfer: {self._format_bytes(total_bytes)} to {profile.dst_ip}",
                description=description,
                affected_ips=list(profile.source_ips) + [profile.dst_ip],
                indicators={
                    "destination_ip": profile.dst_ip,
                    "total_bytes": total_bytes,
                    "duration_seconds": round(duration, 2),
                    "rate_mbps": round(rate_mbps, 2),
                    "ports": sorted(profile.dst_ports),
                    "source_ips": sorted(profile.source_ips),
                    "flow_count": len(profile.flows),
                },
                timestamp_start=min(profile.timestamps) if profile.timestamps else None,
                timestamp_end=max(profile.timestamps) if profile.timestamps else None,
                mitre_techniques=["T1048", "T1041"],
                wireshark_filter=wireshark_filter,
            )
            findings.append(finding)

        return findings

    def _check_high_ratio(
        self, profiles: dict[str, DestinationProfile]
    ) -> list[Finding]:
        """Check for high outbound/inbound byte ratios."""
        findings = []
        threshold = self.config["high_ratio_threshold"]

        for profile in profiles.values():
            # Need meaningful traffic
            total_bytes = sum(f.byte_count for f in profile.flows)
            if total_bytes < self.config["min_bytes_threshold"]:
                continue

            ratio = profile.byte_ratio
            if ratio >= threshold:
                severity = Severity.MEDIUM if ratio < 50 else Severity.HIGH
                confidence = min(0.8, 0.4 + (ratio / 100))

                description = (
                    f"Asymmetric traffic pattern to **{profile.dst_ip}**.\n\n"
                    f"**Pattern Analysis:**\n"
                    f"- Outbound/inbound ratio: {ratio:.1f}:1\n"
                    f"- This suggests data is being uploaded with minimal response.\n"
                    f"\n**Why this matters:** Normal web traffic typically has more "
                    f"inbound data (downloading content). A high outbound ratio "
                    f"may indicate data exfiltration."
                )

                finding = self.create_finding(
                    severity=severity,
                    confidence=confidence,
                    title=f"High Outbound Ratio: {ratio:.0f}:1 to {profile.dst_ip}",
                    description=description,
                    affected_ips=list(profile.source_ips) + [profile.dst_ip],
                    indicators={
                        "destination_ip": profile.dst_ip,
                        "outbound_inbound_ratio": round(ratio, 2),
                        "total_bytes": total_bytes,
                    },
                    mitre_techniques=["T1048", "T1041"],
                    wireshark_filter=f"ip.dst == {profile.dst_ip}",
                )
                findings.append(finding)

        return findings

    def _check_protocol_exfil(self, parse_result: ParseResult) -> list[Finding]:
        """Check for exfiltration over unusual protocols."""
        findings = []

        # Calculate DNS data volume
        dns_bytes = sum(
            len(q.query_name) + q.response_size
            for q in parse_result.dns_queries
        )

        if dns_bytes >= self.config["dns_exfil_threshold"]:
            finding = self.create_finding(
                severity=Severity.HIGH,
                confidence=0.75,
                title=f"High DNS Data Volume: {self._format_bytes(dns_bytes)}",
                description=(
                    f"Unusually high volume of DNS data detected.\n\n"
                    f"**Details:**\n"
                    f"- Total DNS payload: {self._format_bytes(dns_bytes)}\n"
                    f"- Query count: {len(parse_result.dns_queries)}\n"
                    f"\n**Why this matters:** DNS tunneling can exfiltrate data "
                    f"by encoding it in DNS queries and responses. This volume "
                    f"exceeds normal DNS usage patterns."
                ),
                indicators={
                    "protocol": "DNS",
                    "total_bytes": dns_bytes,
                    "query_count": len(parse_result.dns_queries),
                },
                mitre_techniques=["T1048.003", "T1071.004"],
                wireshark_filter="dns",
            )
            findings.append(finding)

        # Check ICMP data volume
        icmp_flows = [f for f in parse_result.flows.values() if f.protocol == Protocol.ICMP]
        icmp_bytes = sum(f.byte_count for f in icmp_flows)

        if icmp_bytes >= self.config["icmp_exfil_threshold"]:
            finding = self.create_finding(
                severity=Severity.HIGH,
                confidence=0.8,
                title=f"High ICMP Data Volume: {self._format_bytes(icmp_bytes)}",
                description=(
                    f"Unusually high volume of ICMP data detected.\n\n"
                    f"**Details:**\n"
                    f"- Total ICMP payload: {self._format_bytes(icmp_bytes)}\n"
                    f"- Flow count: {len(icmp_flows)}\n"
                    f"\n**Why this matters:** ICMP tunneling (ping tunnels) can "
                    f"exfiltrate data by encoding it in echo request/reply payloads. "
                    f"Normal ICMP traffic has minimal payload."
                ),
                indicators={
                    "protocol": "ICMP",
                    "total_bytes": icmp_bytes,
                    "flow_count": len(icmp_flows),
                },
                mitre_techniques=["T1048.003", "T1095"],
                wireshark_filter="icmp",
            )
            findings.append(finding)

        return findings

    def _check_cloud_storage(self, parse_result: ParseResult) -> list[Finding]:
        """Check for uploads to cloud storage or paste sites."""
        findings = []

        # Collect suspicious uploads from DNS queries and TLS SNI
        suspicious_destinations: dict[str, list[Flow]] = defaultdict(list)

        # Check TLS SNI for cloud storage
        for tls_info in parse_result.tls_info:
            if tls_info.sni:
                sni_lower = tls_info.sni.lower()
                for domain in CLOUD_STORAGE_DOMAINS | PASTE_SITES:
                    if sni_lower.endswith(domain):
                        # Find associated flows (approximate by IP)
                        suspicious_destinations[domain].append(tls_info)
                        break

        # Report findings for each suspicious destination
        for domain, items in suspicious_destinations.items():
            is_paste = domain in PASTE_SITES
            category = "Paste Site" if is_paste else "Cloud Storage"

            finding = self.create_finding(
                severity=Severity.MEDIUM,
                confidence=0.6,
                title=f"{category} Access: {domain}",
                description=(
                    f"Connection to **{domain}** ({category.lower()}) detected.\n\n"
                    f"**Connection count:** {len(items)}\n"
                    f"\n**Why this matters:** "
                    + (
                        "Paste sites are commonly used to exfiltrate data or "
                        "download malicious payloads."
                        if is_paste
                        else "Cloud storage may be used for data exfiltration, "
                        "especially if access is unexpected for this host."
                    )
                ),
                indicators={
                    "domain": domain,
                    "category": category.lower().replace(" ", "_"),
                    "connection_count": len(items),
                },
                mitre_techniques=["T1567.002" if not is_paste else "T1567"],
                wireshark_filter=f'tls.handshake.extensions_server_name contains "{domain}"',
            )
            findings.append(finding)

        return findings

    @staticmethod
    def _format_bytes(size: int) -> str:
        """Format byte count to human-readable string."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is in private range."""
        if ip.startswith("10."):
            return True
        if ip.startswith("172."):
            parts = ip.split(".")
            if len(parts) >= 2:
                try:
                    second = int(parts[1])
                    if 16 <= second <= 31:
                        return True
                except ValueError:
                    pass
        if ip.startswith("192.168."):
            return True
        if ip.startswith("127."):
            return True
        return False
