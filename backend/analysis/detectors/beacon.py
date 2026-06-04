"""
NetSpecter Beacon Detector

Detects C2 beacon communication patterns by analyzing connection timing regularity.
Beacons typically connect at fixed intervals (e.g., every 60 seconds) with minimal jitter.
"""

import statistics
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

import structlog

from backend.analysis.detectors.base import BaseDetector, Finding, Severity
from backend.analysis.models import Flow, ParseResult

logger = structlog.get_logger(__name__)


@dataclass
class BeaconCandidate:
    """Potential beacon communication pattern."""

    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    timestamps: list[float]
    packet_count: int
    byte_count: int

    @property
    def interval_count(self) -> int:
        """Number of intervals between connections."""
        return len(self.timestamps) - 1 if len(self.timestamps) > 1 else 0


class BeaconDetector(BaseDetector):
    """
    Detects C2 beacon patterns by analyzing connection timing.

    Beacons are characterized by:
    - Regular time intervals between connections
    - Low jitter (standard deviation of intervals)
    - Sustained activity over time
    - Often to a single destination

    MITRE ATT&CK: T1071 (Application Layer Protocol), T1095 (Non-Application Layer Protocol)
    """

    name = "beacon"
    description = "C2 beacon communication detector"
    version = "1.0.0"

    # Default configuration
    DEFAULT_CONFIG = {
        # Minimum connections to consider for beacon detection
        "min_connections": 10,
        # Maximum jitter (coefficient of variation) to consider regular
        "max_jitter_cv": 0.15,  # 15% variation
        # Common beacon intervals to check (seconds)
        "known_intervals": [30, 60, 120, 180, 300, 600, 900, 1800, 3600],
        # Tolerance for interval matching (percentage)
        "interval_tolerance": 0.1,  # 10%
        # Minimum session duration (seconds)
        "min_duration": 300,  # 5 minutes
        # Minimum regularity score to report
        "min_regularity_score": 0.7,
    }

    def _setup(self) -> None:
        """Initialize detector configuration."""
        for key, default in self.DEFAULT_CONFIG.items():
            if key not in self.config:
                self.config[key] = default

    def detect(self, parse_result: ParseResult) -> list[Finding]:
        """
        Analyze flows for beacon-like timing patterns.

        Args:
            parse_result: Parsed PCAP data.

        Returns:
            List of beacon detection findings.
        """
        findings = []

        # Group flows by source-destination pair
        candidates = self._extract_candidates(list(parse_result.flows.values()))

        logger.debug(
            "beacon_candidates_extracted",
            candidate_count=len(candidates),
        )

        for candidate in candidates:
            finding = self._analyze_candidate(candidate)
            if finding:
                findings.append(finding)

        logger.info(
            "beacon_detection_complete",
            findings_count=len(findings),
        )

        return findings

    def _extract_candidates(self, flows: list[Flow]) -> list[BeaconCandidate]:
        """
        Extract beacon candidates from flows.

        Groups connections by source-destination pair and collects timestamps.
        """
        # Group by (src_ip, dst_ip, dst_port, protocol)
        groups: dict[tuple, list[Flow]] = defaultdict(list)

        for flow in flows:
            # Skip internal-only traffic
            if self._is_private_ip(flow.src_ip) and self._is_private_ip(flow.dst_ip):
                continue

            key = (flow.src_ip, flow.dst_ip, flow.dst_port, flow.protocol)
            groups[key].append(flow)

        candidates = []
        min_connections = self.config["min_connections"]

        for (src_ip, dst_ip, dst_port, protocol), flow_list in groups.items():
            # Need enough connections for pattern analysis
            if len(flow_list) < min_connections:
                continue

            # Collect timestamps and stats
            timestamps = sorted([f.start_time for f in flow_list])
            packet_count = sum(f.packet_count for f in flow_list)
            byte_count = sum(f.byte_count for f in flow_list)

            # Check minimum duration
            duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
            if duration < self.config["min_duration"]:
                continue

            candidates.append(
                BeaconCandidate(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol,
                    timestamps=timestamps,
                    packet_count=packet_count,
                    byte_count=byte_count,
                )
            )

        return candidates

    def _analyze_candidate(self, candidate: BeaconCandidate) -> Finding | None:
        """
        Analyze a candidate for beacon characteristics.

        Returns Finding if beacon pattern detected, None otherwise.
        """
        if candidate.interval_count < 2:
            return None

        # Calculate inter-arrival times
        intervals = []
        for i in range(1, len(candidate.timestamps)):
            delta = candidate.timestamps[i] - candidate.timestamps[i - 1]
            intervals.append(delta)

        if not intervals:
            return None

        # Calculate statistics
        mean_interval = statistics.mean(intervals)
        if mean_interval <= 0:
            return None

        try:
            stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        except statistics.StatisticsError:
            stdev_interval = 0

        # Coefficient of variation (jitter measure)
        cv = stdev_interval / mean_interval if mean_interval > 0 else float("inf")

        # Check if jitter is low enough
        if cv > self.config["max_jitter_cv"]:
            return None

        # Calculate regularity score (inverse of CV, capped at 1.0)
        regularity_score = max(0, min(1.0, 1 - (cv / self.config["max_jitter_cv"])))

        if regularity_score < self.config["min_regularity_score"]:
            return None

        # Check for known beacon intervals
        matched_interval = self._match_known_interval(mean_interval)

        # Calculate confidence based on multiple factors
        confidence = self._calculate_confidence(
            regularity_score=regularity_score,
            interval_count=candidate.interval_count,
            duration=candidate.timestamps[-1] - candidate.timestamps[0],
            matched_interval=matched_interval,
        )

        # Determine severity based on confidence and characteristics
        if confidence >= 0.9 and matched_interval:
            severity = Severity.HIGH
        elif confidence >= 0.7:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        # Build description
        duration_mins = (candidate.timestamps[-1] - candidate.timestamps[0]) / 60
        description = (
            f"Regular connection pattern detected from {candidate.src_ip} to "
            f"{candidate.dst_ip}:{candidate.dst_port} ({candidate.protocol}).\n\n"
            f"**Pattern Analysis:**\n"
            f"- Mean interval: {mean_interval:.1f}s (±{stdev_interval:.1f}s)\n"
            f"- Regularity score: {regularity_score:.1%}\n"
            f"- Duration: {duration_mins:.1f} minutes\n"
            f"- Connection count: {candidate.interval_count + 1}\n"
        )

        if matched_interval:
            description += f"- Matches known beacon interval: {matched_interval}s\n"

        description += (
            f"\n**Why this matters:** C2 frameworks (Cobalt Strike, Metasploit, etc.) "
            f"often use fixed callback intervals. The low jitter ({cv:.1%}) suggests "
            f"automated rather than human-initiated connections."
        )

        # Generate Wireshark filter
        wireshark_filter = (
            f"ip.src == {candidate.src_ip} && "
            f"ip.dst == {candidate.dst_ip} && "
            f"{'tcp' if candidate.protocol == 'TCP' else 'udp'}.dstport == {candidate.dst_port}"
        )

        return self.create_finding(
            severity=severity,
            confidence=confidence,
            title=f"C2 Beacon Pattern: {candidate.src_ip} → {candidate.dst_ip}:{candidate.dst_port}",
            description=description,
            affected_ips=[candidate.src_ip, candidate.dst_ip],
            affected_flows=[
                f"{candidate.src_ip}:{candidate.dst_port}->{candidate.dst_ip}:{candidate.dst_port}/{candidate.protocol}"
            ],
            indicators={
                "mean_interval": round(mean_interval, 2),
                "stdev_interval": round(stdev_interval, 2),
                "coefficient_of_variation": round(cv, 4),
                "regularity_score": round(regularity_score, 4),
                "connection_count": candidate.interval_count + 1,
                "duration_seconds": round(candidate.timestamps[-1] - candidate.timestamps[0], 2),
                "matched_known_interval": matched_interval,
                "packet_count": candidate.packet_count,
                "byte_count": candidate.byte_count,
            },
            timestamp_start=candidate.timestamps[0],
            timestamp_end=candidate.timestamps[-1],
            mitre_techniques=["T1071", "T1571"],
            wireshark_filter=wireshark_filter,
        )

    def _match_known_interval(self, mean_interval: float) -> int | None:
        """Check if mean interval matches a known beacon interval."""
        tolerance = self.config["interval_tolerance"]

        for known in self.config["known_intervals"]:
            lower = known * (1 - tolerance)
            upper = known * (1 + tolerance)
            if lower <= mean_interval <= upper:
                return known

        return None

    def _calculate_confidence(
        self,
        regularity_score: float,
        interval_count: int,
        duration: float,
        matched_interval: int | None,
    ) -> float:
        """Calculate overall confidence score for beacon detection."""
        # Base confidence from regularity
        confidence = regularity_score * 0.5

        # Bonus for more intervals (more data = more confidence)
        if interval_count >= 100:
            confidence += 0.2
        elif interval_count >= 50:
            confidence += 0.15
        elif interval_count >= 20:
            confidence += 0.1
        else:
            confidence += 0.05

        # Bonus for longer duration
        if duration >= 3600:  # 1 hour
            confidence += 0.15
        elif duration >= 1800:  # 30 mins
            confidence += 0.1
        elif duration >= 600:  # 10 mins
            confidence += 0.05

        # Bonus for matching known interval
        if matched_interval:
            confidence += 0.15

        return min(1.0, confidence)

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
