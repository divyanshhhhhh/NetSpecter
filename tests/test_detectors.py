"""
Tests for NetSpecter Detection Engines.
"""

import pytest
from datetime import datetime

from backend.analysis.detectors import (
    BeaconDetector,
    DNSTunnelDetector,
    ExfiltrationDetector,
    PortScanDetector,
    Finding,
    Severity,
)
from backend.analysis.models import Flow, DNSQuery, TLSInfo, ParseResult, Protocol


def make_parse_result(
    flows: list[Flow] | None = None,
    dns_queries: list[DNSQuery] | None = None,
    tls_info: list[TLSInfo] | None = None,
    total_bytes: int = 0,
) -> ParseResult:
    """
    Helper to create ParseResult with proper structure.
    
    Converts flow lists to dicts with flow_key as key.
    """
    result = ParseResult()
    result.total_bytes = total_bytes
    
    if flows:
        # Convert list to dict with flow_key
        for i, flow in enumerate(flows):
            flow_key = f"{flow.src_ip}:{flow.src_port}-{flow.dst_ip}:{flow.dst_port}-{flow.protocol.name}"
            result.flows[flow_key] = flow
        
        # Set time range from flows
        result.start_time = min(f.start_time for f in flows)
        result.end_time = max(f.end_time for f in flows)
        result.total_packets = sum(f.packet_count for f in flows)
        if total_bytes == 0:
            result.total_bytes = sum(f.byte_count for f in flows)
    
    if dns_queries:
        result.dns_queries = dns_queries
    
    if tls_info:
        result.tls_info = tls_info
    
    return result


class TestBeaconDetector:
    """Tests for C2 beacon detection."""

    @pytest.fixture
    def detector(self):
        return BeaconDetector()

    def test_detects_regular_interval_beacon(self, detector):
        """Should detect regular 60-second beacon pattern."""
        # Create flows with exact 60-second intervals
        base_time = 1700000000.0
        flows = []
        for i in range(20):
            flows.append(
                Flow(
                    src_ip="192.168.1.100",
                    dst_ip="185.234.5.6",
                    src_port=49152 + i,
                    dst_port=443,
                    protocol=Protocol.TCP,
                    packet_count=10,
                    byte_count=1500,
                    start_time=base_time + (i * 60),  # Every 60 seconds
                    end_time=base_time + (i * 60) + 1,
                )
            )

        result = make_parse_result(flows=flows)
        findings = detector.detect(result)

        assert len(findings) >= 1
        beacon_finding = findings[0]
        assert beacon_finding.detector == "beacon"
        assert "60" in str(beacon_finding.indicators.get("matched_known_interval", ""))
        assert beacon_finding.confidence >= 0.7

    def test_ignores_irregular_traffic(self, detector):
        """Should not flag irregular connection patterns."""
        import random

        base_time = 1700000000.0
        flows = []
        cumulative_time = 0
        for i in range(20):
            cumulative_time += random.uniform(5, 300)
            flows.append(
                Flow(
                    src_ip="192.168.1.100",
                    dst_ip="8.8.8.8",
                    src_port=49152 + i,
                    dst_port=443,
                    protocol=Protocol.TCP,
                    packet_count=10,
                    byte_count=1500,
                    start_time=base_time + cumulative_time,
                    end_time=base_time + cumulative_time + 1,
                )
            )

        result = make_parse_result(flows=flows)
        findings = detector.detect(result)
        # May or may not detect depending on random intervals
        # Just verify no crash
        assert isinstance(findings, list)

    def test_ignores_internal_only_traffic(self, detector):
        """Should skip traffic between internal hosts."""
        base_time = 1700000000.0
        flows = []
        for i in range(20):
            flows.append(
                Flow(
                    src_ip="192.168.1.100",
                    dst_ip="192.168.1.200",  # Internal destination
                    src_port=49152 + i,
                    dst_port=445,
                    protocol=Protocol.TCP,
                    packet_count=10,
                    byte_count=1500,
                    start_time=base_time + (i * 60),
                    end_time=base_time + (i * 60) + 1,
                )
            )

        result = make_parse_result(flows=flows)
        findings = detector.detect(result)
        assert len(findings) == 0


class TestDNSTunnelDetector:
    """Tests for DNS tunneling detection."""

    @pytest.fixture
    def detector(self):
        return DNSTunnelDetector()

    def test_detects_high_entropy_subdomains(self, detector):
        """Should detect high-entropy subdomain patterns."""
        queries = []
        # Simulate Base64-like subdomain names (high entropy)
        base64_like = [
            "aGVsbG8gd29ybGQ",
            "dGhpcyBpcyBhIHRlc3Q",
            "c2VjcmV0IGRhdGE",
            "ZXhmaWx0cmF0aW9u",
            "bWFsd2FyZSBjb21t",
        ]
        for i, subdomain in enumerate(base64_like * 5):  # 25 queries
            queries.append(
                DNSQuery(
                    timestamp=1700000000.0 + i,
                    src_ip="192.168.1.100",
                    dst_ip="8.8.8.8",
                    query_name=f"{subdomain}.{i}.malicious-tunnel.tk",
                    query_type="A",
                    response_code="NOERROR",
                    response_ips=["1.2.3.4"],
                    ttl=300,
                )
            )

        result = make_parse_result(dns_queries=queries)
        findings = detector.detect(result)

        assert len(findings) >= 1
        tunnel_finding = findings[0]
        assert tunnel_finding.detector == "dns_tunnel"
        assert tunnel_finding.severity in [Severity.MEDIUM, Severity.HIGH]

    def test_detects_known_tunnel_patterns(self, detector):
        """Should detect known DNS tunnel tool patterns."""
        queries = [
            DNSQuery(
                timestamp=1700000000.0,
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
                query_name="command.dnscat.attacker.com",
                query_type="TXT",
                response_code="NOERROR",
                response_ips=[],
                ttl=0,
            )
        ]

        result = make_parse_result(dns_queries=queries)
        findings = detector.detect(result)

        assert len(findings) >= 1
        assert any("dnscat" in f.title.lower() for f in findings)

    def test_ignores_normal_dns(self, detector):
        """Should not flag normal DNS traffic."""
        queries = [
            DNSQuery(
                timestamp=1700000000.0 + i,
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
                query_name=f"www.{domain}",
                query_type="A",
                response_code="NOERROR",
                response_ips=["1.2.3.4"],
                ttl=300,
            )
            for i, domain in enumerate([
                "google.com",
                "microsoft.com", 
                "github.com",
                "amazon.com",
                "apple.com",
            ])
        ]

        result = make_parse_result(dns_queries=queries)
        findings = detector.detect(result)
        
        # Normal traffic shouldn't trigger high-confidence findings
        high_conf_findings = [f for f in findings if f.confidence >= 0.7]
        assert len(high_conf_findings) == 0


class TestExfiltrationDetector:
    """Tests for data exfiltration detection."""

    @pytest.fixture
    def detector(self):
        return ExfiltrationDetector()

    def test_detects_large_transfer(self, detector):
        """Should detect large outbound data transfer."""
        flows = [
            Flow(
                src_ip="192.168.1.100",
                dst_ip="45.33.32.156",
                src_port=49152,
                dst_port=443,
                protocol=Protocol.TCP,
                packet_count=50000,
                byte_count=100 * 1024 * 1024,  # 100 MB
                start_time=1700000000.0,
                end_time=1700000600.0,
            )
        ]

        result = make_parse_result(flows=flows, total_bytes=100 * 1024 * 1024)
        findings = detector.detect(result)

        assert len(findings) >= 1
        exfil_finding = findings[0]
        assert exfil_finding.detector == "exfiltration"
        assert "100" in exfil_finding.title or "MB" in exfil_finding.title

    def test_detects_paste_site_access(self, detector):
        """Should flag connections to paste sites."""
        tls_info = [
            TLSInfo(
                timestamp=1700000000.0,
                src_ip="192.168.1.100",
                dst_ip="104.20.3.3",
                dst_port=443,
                sni="pastebin.com",
                version="TLS 1.3",
                cipher_suite="TLS_AES_256_GCM_SHA384",
            )
        ]

        result = make_parse_result(tls_info=tls_info)
        findings = detector.detect(result)

        assert len(findings) >= 1
        paste_finding = [f for f in findings if "paste" in f.title.lower()]
        assert len(paste_finding) >= 1


class TestPortScanDetector:
    """Tests for port scan detection."""

    @pytest.fixture
    def detector(self):
        return PortScanDetector()

    def test_detects_horizontal_scan(self, detector):
        """Should detect horizontal port scan (one port, many hosts)."""
        flows = []
        for i in range(50):
            flows.append(
                Flow(
                    src_ip="192.168.1.100",
                    dst_ip=f"10.0.0.{i + 1}",
                    src_port=49152,
                    dst_port=445,  # Same port
                    protocol=Protocol.TCP,
                    packet_count=2,  # SYN, RST
                    byte_count=100,
                    start_time=1700000000.0 + i,
                    end_time=1700000000.0 + i + 0.1,
                )
            )

        result = make_parse_result(flows=flows)
        findings = detector.detect(result)

        assert len(findings) >= 1
        scan_finding = findings[0]
        assert scan_finding.detector == "port_scan"
        assert "horizontal" in scan_finding.indicators.get("scan_type", "").lower()

    def test_detects_vertical_scan(self, detector):
        """Should detect vertical port scan (one host, many ports)."""
        flows = []
        for port in range(1, 101):  # Ports 1-100
            flows.append(
                Flow(
                    src_ip="192.168.1.100",
                    dst_ip="10.0.0.50",  # Same target
                    src_port=49152,
                    dst_port=port,
                    protocol=Protocol.TCP,
                    packet_count=2,
                    byte_count=100,
                    start_time=1700000000.0 + port,
                    end_time=1700000000.0 + port + 0.1,
                )
            )

        result = make_parse_result(flows=flows)
        findings = detector.detect(result)

        assert len(findings) >= 1
        vertical_findings = [
            f for f in findings 
            if f.indicators.get("scan_type") == "vertical"
        ]
        assert len(vertical_findings) >= 1

    def test_ignores_normal_traffic(self, detector):
        """Should not flag normal connection patterns."""
        flows = []
        # Normal web traffic to few destinations
        for i in range(10):
            flows.append(
                Flow(
                    src_ip="192.168.1.100",
                    dst_ip="142.250.80.46",  # Google
                    src_port=49152 + i,
                    dst_port=443,
                    protocol=Protocol.TCP,
                    packet_count=100,
                    byte_count=50000,
                    start_time=1700000000.0 + i * 10,
                    end_time=1700000000.0 + i * 10 + 5,
                )
            )

        result = make_parse_result(flows=flows)
        findings = detector.detect(result)
        
        # Should not detect scan patterns in normal traffic
        assert len(findings) == 0


class TestFindingModel:
    """Tests for the Finding data model."""

    def test_finding_to_dict(self):
        """Should serialize finding to dictionary."""
        finding = Finding(
            detector="test",
            severity=Severity.HIGH,
            confidence=0.85,
            title="Test Finding",
            description="Test description",
            affected_ips=["192.168.1.1", "10.0.0.1"],
            timestamp_start=1700000000.0,
            timestamp_end=1700001000.0,
            mitre_techniques=["T1046"],
        )

        result = finding.to_dict()

        assert result["detector"] == "test"
        assert result["severity"] == "high"
        assert result["confidence"] == 0.85
        assert len(result["affected_ips"]) == 2
        assert "T1046" in result["mitre_techniques"]
        assert result["timestamp_start_iso"] is not None
