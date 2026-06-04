"""
NetSpecter Port Scan Detector

Detects port scanning activity by analyzing connection patterns,
including horizontal scans (one port, many hosts) and vertical scans
(one host, many ports).
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

from backend.analysis.detectors.base import BaseDetector, Finding, Severity
from backend.analysis.models import Flow, ParseResult

logger = structlog.get_logger(__name__)


@dataclass
class ScanProfile:
    """Profile of potential scanning activity from a source."""

    src_ip: str
    dst_ips: set[str] = field(default_factory=set)
    dst_ports: set[int] = field(default_factory=set)
    syn_only_count: int = 0
    total_connections: int = 0
    failed_connections: int = 0
    timestamps: list[float] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)

    @property
    def unique_hosts(self) -> int:
        return len(self.dst_ips)

    @property
    def unique_ports(self) -> int:
        return len(self.dst_ports)

    @property
    def failure_rate(self) -> float:
        if self.total_connections == 0:
            return 0.0
        return self.failed_connections / self.total_connections


@dataclass
class PortDistribution:
    """Port connection distribution for scan type detection."""

    port: int
    target_ips: set[str] = field(default_factory=set)
    flows: list[Flow] = field(default_factory=list)


class PortScanDetector(BaseDetector):
    """
    Detects port scanning activity.

    Detection signals include:
    - Many connection attempts to different hosts (horizontal scan)
    - Many connection attempts to different ports (vertical scan)
    - High rate of SYN-only packets (stealth scan)
    - High connection failure rate
    - Sequential port access patterns

    MITRE ATT&CK: T1046 (Network Service Discovery)
    """

    name = "port_scan"
    description = "Port scanning detection"
    version = "1.0.0"

    DEFAULT_CONFIG = {
        # Minimum unique destinations for horizontal scan
        "horizontal_scan_threshold": 10,
        # Minimum unique ports for vertical scan
        "vertical_scan_threshold": 20,
        # SYN-only ratio to consider stealth scan
        "syn_only_ratio_threshold": 0.8,
        # Minimum connections to analyze
        "min_connections": 15,
        # Connection failure rate threshold
        "failure_rate_threshold": 0.7,
        # Time window for rapid scanning (seconds)
        "rapid_scan_window": 60,
        # Minimum connections in rapid window
        "rapid_scan_min_connections": 50,
        # Well-known ports to flag
        "sensitive_ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                           993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 
                           8080, 8443, 27017],
    }

    def _setup(self) -> None:
        """Initialize detector configuration."""
        for key, default in self.DEFAULT_CONFIG.items():
            if key not in self.config:
                self.config[key] = default

    def detect(self, parse_result: ParseResult) -> list[Finding]:
        """
        Analyze flows for port scanning patterns.

        Args:
            parse_result: Parsed PCAP data.

        Returns:
            List of port scan detection findings.
        """
        findings = []

        # Build scan profiles for each source IP
        profiles = self._build_profiles(list(parse_result.flows.values()))

        logger.debug(
            "scan_profiles_built",
            profile_count=len(profiles),
        )

        for src_ip, profile in profiles.items():
            # Check for horizontal scan (many hosts, few ports)
            horizontal_finding = self._check_horizontal_scan(profile)
            if horizontal_finding:
                findings.append(horizontal_finding)

            # Check for vertical scan (one host, many ports)
            vertical_finding = self._check_vertical_scan(profile)
            if vertical_finding:
                findings.append(vertical_finding)

            # Check for stealth scan (SYN-only)
            stealth_finding = self._check_stealth_scan(profile)
            if stealth_finding:
                findings.append(stealth_finding)

            # Check for rapid scanning
            rapid_finding = self._check_rapid_scan(profile)
            if rapid_finding:
                findings.append(rapid_finding)

        logger.info(
            "port_scan_detection_complete",
            findings_count=len(findings),
        )

        return findings

    def _build_profiles(self, flows: list[Flow]) -> dict[str, ScanProfile]:
        """Build scan profiles for each source IP."""
        profiles: dict[str, ScanProfile] = {}

        for flow in flows:
            # Skip non-TCP flows for scan detection
            if flow.protocol != "TCP":
                continue

            src_ip = flow.src_ip

            if src_ip not in profiles:
                profiles[src_ip] = ScanProfile(src_ip=src_ip)

            profile = profiles[src_ip]
            profile.dst_ips.add(flow.dst_ip)
            profile.dst_ports.add(flow.dst_port)
            profile.total_connections += 1
            profile.timestamps.append(flow.start_time)
            profile.flows.append(flow)

            # Check for SYN-only (incomplete handshake indicator)
            # Heuristic: very few packets and bytes suggests incomplete connection
            if flow.packet_count <= 3 and flow.byte_count < 200:
                profile.syn_only_count += 1
                profile.failed_connections += 1

        return profiles

    def _check_horizontal_scan(self, profile: ScanProfile) -> Finding | None:
        """Check for horizontal scan (one port, many hosts)."""
        if profile.total_connections < self.config["min_connections"]:
            return None

        threshold = self.config["horizontal_scan_threshold"]

        if profile.unique_hosts < threshold:
            return None

        # Check if targeting few ports (characteristic of horizontal scan)
        if profile.unique_ports > 5:
            # Too many ports for classic horizontal scan
            return None

        # Calculate ratio of hosts to ports
        host_port_ratio = profile.unique_hosts / max(1, profile.unique_ports)

        if host_port_ratio < 3:
            return None

        # Determine severity based on scale
        if profile.unique_hosts >= 100:
            severity = Severity.HIGH
            confidence = 0.85
        elif profile.unique_hosts >= 50:
            severity = Severity.MEDIUM
            confidence = 0.75
        else:
            severity = Severity.LOW
            confidence = 0.6

        # Find the most targeted ports
        port_targets: dict[int, set[str]] = defaultdict(set)
        for flow in profile.flows:
            port_targets[flow.dst_port].add(flow.dst_ip)

        top_ports = sorted(port_targets.items(), key=lambda x: len(x[1]), reverse=True)[:5]

        description = (
            f"Horizontal port scan detected from **{profile.src_ip}**.\n\n"
            f"**Scan Details:**\n"
            f"- Unique hosts targeted: {profile.unique_hosts}\n"
            f"- Ports used: {', '.join(str(p) for p in sorted(profile.dst_ports))}\n"
            f"- Total connections: {profile.total_connections}\n"
            f"- Failure rate: {profile.failure_rate:.1%}\n"
            f"\n**Top targeted ports:**\n"
        )
        for port, ips in top_ports:
            description += f"- Port {port}: {len(ips)} hosts\n"

        description += (
            f"\n**Why this matters:** Horizontal scans probe many hosts for a specific "
            f"service, often to find vulnerable systems (e.g., SMB, SSH). This pattern "
            f"is consistent with reconnaissance or worm propagation."
        )

        wireshark_filter = f"ip.src == {profile.src_ip} && tcp.flags.syn == 1"

        return self.create_finding(
            severity=severity,
            confidence=confidence,
            title=f"Horizontal Scan: {profile.src_ip} → {profile.unique_hosts} hosts",
            description=description,
            affected_ips=[profile.src_ip] + list(profile.dst_ips)[:20],
            indicators={
                "scan_type": "horizontal",
                "source_ip": profile.src_ip,
                "unique_hosts": profile.unique_hosts,
                "unique_ports": profile.unique_ports,
                "total_connections": profile.total_connections,
                "failure_rate": round(profile.failure_rate, 3),
                "top_ports": [(p, len(ips)) for p, ips in top_ports],
            },
            timestamp_start=min(profile.timestamps) if profile.timestamps else None,
            timestamp_end=max(profile.timestamps) if profile.timestamps else None,
            mitre_techniques=["T1046", "T1018"],
            wireshark_filter=wireshark_filter,
        )

    def _check_vertical_scan(self, profile: ScanProfile) -> Finding | None:
        """Check for vertical scan (one host, many ports)."""
        if profile.total_connections < self.config["min_connections"]:
            return None

        threshold = self.config["vertical_scan_threshold"]

        # For vertical scan, we need many ports but few destinations
        if profile.unique_ports < threshold:
            return None

        if profile.unique_hosts > 3:
            # Too many hosts for classic vertical scan
            return None

        # Determine severity
        if profile.unique_ports >= 100:
            severity = Severity.HIGH
            confidence = 0.85
        elif profile.unique_ports >= 50:
            severity = Severity.MEDIUM
            confidence = 0.75
        else:
            severity = Severity.LOW
            confidence = 0.6

        # Check for sequential ports (nmap-style)
        sorted_ports = sorted(profile.dst_ports)
        sequential_runs = self._count_sequential_runs(sorted_ports)

        # Check for sensitive port targeting
        sensitive_hit = [p for p in profile.dst_ports if p in self.config["sensitive_ports"]]

        target_hosts = list(profile.dst_ips)[:5]

        description = (
            f"Vertical port scan detected from **{profile.src_ip}**.\n\n"
            f"**Scan Details:**\n"
            f"- Target host(s): {', '.join(target_hosts)}\n"
            f"- Unique ports scanned: {profile.unique_ports}\n"
            f"- Port range: {min(sorted_ports)} - {max(sorted_ports)}\n"
            f"- Total connections: {profile.total_connections}\n"
            f"- Sequential port runs: {sequential_runs}\n"
        )

        if sensitive_hit:
            description += f"- Sensitive ports hit: {', '.join(str(p) for p in sensitive_hit[:10])}\n"

        description += (
            f"\n**Why this matters:** Vertical scans enumerate services on a target "
            f"host, typically for vulnerability assessment or attack preparation. "
            f"{'Sequential ports suggest an automated scanning tool.' if sequential_runs > 3 else ''}"
        )

        wireshark_filter = f"ip.src == {profile.src_ip} && ip.dst == {target_hosts[0]}"

        return self.create_finding(
            severity=severity,
            confidence=confidence,
            title=f"Vertical Scan: {profile.src_ip} → {profile.unique_ports} ports",
            description=description,
            affected_ips=[profile.src_ip] + target_hosts,
            indicators={
                "scan_type": "vertical",
                "source_ip": profile.src_ip,
                "target_hosts": target_hosts,
                "unique_ports": profile.unique_ports,
                "port_range": [min(sorted_ports), max(sorted_ports)],
                "sequential_runs": sequential_runs,
                "sensitive_ports_hit": sensitive_hit[:20],
                "total_connections": profile.total_connections,
            },
            timestamp_start=min(profile.timestamps) if profile.timestamps else None,
            timestamp_end=max(profile.timestamps) if profile.timestamps else None,
            mitre_techniques=["T1046"],
            wireshark_filter=wireshark_filter,
        )

    def _check_stealth_scan(self, profile: ScanProfile) -> Finding | None:
        """Check for stealth scan (SYN-only packets)."""
        if profile.total_connections < self.config["min_connections"]:
            return None

        if profile.syn_only_count == 0:
            return None

        syn_ratio = profile.syn_only_count / profile.total_connections

        if syn_ratio < self.config["syn_only_ratio_threshold"]:
            return None

        severity = Severity.MEDIUM
        confidence = min(0.9, 0.5 + syn_ratio * 0.4)

        description = (
            f"Stealth scanning activity detected from **{profile.src_ip}**.\n\n"
            f"**Scan Details:**\n"
            f"- SYN-only connections: {profile.syn_only_count} ({syn_ratio:.1%})\n"
            f"- Total connections: {profile.total_connections}\n"
            f"- Unique destinations: {profile.unique_hosts}\n"
            f"- Unique ports: {profile.unique_ports}\n"
            f"\n**Why this matters:** SYN scans (half-open scans) send only SYN packets "
            f"without completing the TCP handshake. This is a common technique to avoid "
            f"logging on target systems while identifying open ports."
        )

        return self.create_finding(
            severity=severity,
            confidence=confidence,
            title=f"Stealth Scan: {profile.src_ip} ({profile.syn_only_count} SYN-only)",
            description=description,
            affected_ips=[profile.src_ip],
            indicators={
                "scan_type": "stealth_syn",
                "source_ip": profile.src_ip,
                "syn_only_count": profile.syn_only_count,
                "syn_ratio": round(syn_ratio, 3),
                "total_connections": profile.total_connections,
            },
            mitre_techniques=["T1046"],
            wireshark_filter=f"ip.src == {profile.src_ip} && tcp.flags.syn == 1 && tcp.flags.ack == 0",
        )

    def _check_rapid_scan(self, profile: ScanProfile) -> Finding | None:
        """Check for rapid scanning within a time window."""
        if len(profile.timestamps) < self.config["rapid_scan_min_connections"]:
            return None

        window = self.config["rapid_scan_window"]
        min_conns = self.config["rapid_scan_min_connections"]

        # Sort timestamps and use sliding window
        sorted_ts = sorted(profile.timestamps)

        for i, start_ts in enumerate(sorted_ts):
            end_ts = start_ts + window
            # Count connections in window
            count = sum(1 for ts in sorted_ts[i:] if ts <= end_ts)

            if count >= min_conns:
                rate = count / window

                severity = Severity.MEDIUM
                confidence = min(0.85, 0.5 + (count / 200))

                description = (
                    f"Rapid scanning activity detected from **{profile.src_ip}**.\n\n"
                    f"**Scan Details:**\n"
                    f"- Connections in {window}s window: {count}\n"
                    f"- Rate: {rate:.1f} connections/second\n"
                    f"- Unique targets: {profile.unique_hosts} hosts, {profile.unique_ports} ports\n"
                    f"\n**Why this matters:** Rapid connection attempts suggest automated "
                    f"scanning tools like nmap, masscan, or zmap."
                )

                return self.create_finding(
                    severity=severity,
                    confidence=confidence,
                    title=f"Rapid Scan: {profile.src_ip} ({rate:.0f}/sec)",
                    description=description,
                    affected_ips=[profile.src_ip],
                    indicators={
                        "scan_type": "rapid",
                        "source_ip": profile.src_ip,
                        "connections_in_window": count,
                        "window_seconds": window,
                        "rate_per_second": round(rate, 2),
                    },
                    mitre_techniques=["T1046"],
                    wireshark_filter=f"ip.src == {profile.src_ip}",
                )

        return None

    @staticmethod
    def _count_sequential_runs(ports: list[int]) -> int:
        """Count runs of sequential port numbers."""
        if len(ports) < 2:
            return 0

        runs = 0
        in_run = False

        for i in range(1, len(ports)):
            if ports[i] == ports[i - 1] + 1:
                if not in_run:
                    runs += 1
                    in_run = True
            else:
                in_run = False

        return runs
