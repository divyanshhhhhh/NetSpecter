"""
Tests for the Wireshark Filter Generator module.
"""

import pytest

from backend.output.wireshark import (
    WiresharkFilter,
    WiresharkFilterGenerator,
    FilterCategory,
)


class TestWiresharkFilter:
    """Tests for the WiresharkFilter dataclass."""

    def test_basic_filter_creation(self):
        """Test creating a basic filter."""
        f = WiresharkFilter(
            name="Test Filter",
            filter_text="ip.addr == 1.2.3.4",
            description="Test description",
            category=FilterCategory.MALICIOUS_IP,
            severity="high",
            confidence=0.9,
        )
        
        assert f.name == "Test Filter"
        assert f.filter_text == "ip.addr == 1.2.3.4"
        assert f.category == FilterCategory.MALICIOUS_IP
        assert f.confidence == 0.9

    def test_to_dict(self):
        """Test converting filter to dictionary."""
        f = WiresharkFilter(
            name="Test",
            filter_text="tcp.port == 443",
            description="HTTPS traffic",
            category=FilterCategory.PROTOCOL,
            severity="info",
            confidence=1.0,
            related_finding_id="finding-123",
        )
        
        d = f.to_dict()
        
        assert d["name"] == "Test"
        assert d["filter"] == "tcp.port == 443"
        assert d["category"] == "protocol"
        assert d["related_finding_id"] == "finding-123"


class TestWiresharkFilterGenerator:
    """Tests for the WiresharkFilterGenerator class."""

    def test_init(self):
        """Test generator initialization."""
        gen = WiresharkFilterGenerator()
        assert len(gen.filters) == 0

    def test_add_ip_filter(self):
        """Test adding IP filter."""
        gen = WiresharkFilterGenerator()
        f = gen.add_ip_filter("8.8.8.8", name="Google DNS")
        
        assert f is not None
        assert f.filter_text == "ip.addr == 8.8.8.8"
        assert len(gen.filters) == 1

    def test_add_ip_filter_src_direction(self):
        """Test adding IP filter with source direction."""
        gen = WiresharkFilterGenerator()
        f = gen.add_ip_filter("192.168.1.1", direction="src")
        
        assert f is not None
        assert f.filter_text == "ip.src == 192.168.1.1"

    def test_add_ip_filter_dst_direction(self):
        """Test adding IP filter with destination direction."""
        gen = WiresharkFilterGenerator()
        f = gen.add_ip_filter("10.0.0.1", direction="dst")
        
        assert f is not None
        assert f.filter_text == "ip.dst == 10.0.0.1"

    def test_add_ip_filter_invalid_ip(self):
        """Test that invalid IPs are rejected."""
        gen = WiresharkFilterGenerator()
        f = gen.add_ip_filter("not.an.ip")
        
        assert f is None
        assert len(gen.filters) == 0

    def test_add_ip_filter_duplicate(self):
        """Test that duplicate filters are skipped."""
        gen = WiresharkFilterGenerator()
        f1 = gen.add_ip_filter("8.8.8.8")
        f2 = gen.add_ip_filter("8.8.8.8")
        
        assert f1 is not None
        assert f2 is None
        assert len(gen.filters) == 1

    def test_add_conversation_filter(self):
        """Test adding conversation filter."""
        gen = WiresharkFilterGenerator()
        f = gen.add_conversation_filter(
            ip1="192.168.1.100",
            ip2="8.8.8.8",
            port1=12345,
            port2=443,
            protocol="tcp",
        )
        
        assert f is not None
        assert "ip.addr == 192.168.1.100" in f.filter_text
        assert "ip.addr == 8.8.8.8" in f.filter_text
        assert "tcp.port == 12345" in f.filter_text
        assert "tcp.port == 443" in f.filter_text

    def test_add_subnet_filter(self):
        """Test adding subnet filter."""
        gen = WiresharkFilterGenerator()
        f = gen.add_subnet_filter("192.168.1.0/24")
        
        assert f is not None
        assert f.filter_text == "ip.addr == 192.168.1.0/24"

    def test_add_port_filter(self):
        """Test adding port filter."""
        gen = WiresharkFilterGenerator()
        f = gen.add_port_filter(443, protocol="tcp")
        
        assert f is not None
        assert f.filter_text == "tcp.port == 443"

    def test_add_port_filter_udp(self):
        """Test adding UDP port filter."""
        gen = WiresharkFilterGenerator()
        f = gen.add_port_filter(53, protocol="udp")
        
        assert f is not None
        assert f.filter_text == "udp.port == 53"

    def test_add_port_filter_with_direction(self):
        """Test adding port filter with direction."""
        gen = WiresharkFilterGenerator()
        f = gen.add_port_filter(80, direction="dst")
        
        assert f is not None
        assert f.filter_text == "tcp.dstport == 80"

    def test_add_port_range_filter(self):
        """Test adding port range filter."""
        gen = WiresharkFilterGenerator()
        f = gen.add_port_range_filter(8000, 9000)
        
        assert f is not None
        assert "tcp.port >= 8000" in f.filter_text
        assert "tcp.port <= 9000" in f.filter_text

    def test_add_dns_query_filter(self):
        """Test adding DNS query filter."""
        gen = WiresharkFilterGenerator()
        f = gen.add_dns_query_filter("example.com")
        
        assert f is not None
        assert f.filter_text == 'dns.qry.name contains "example.com"'

    def test_add_dns_query_filter_exact(self):
        """Test adding exact match DNS query filter."""
        gen = WiresharkFilterGenerator()
        f = gen.add_dns_query_filter("www.example.com", exact_match=True)
        
        assert f is not None
        assert f.filter_text == 'dns.qry.name == "www.example.com"'

    def test_add_protocol_filter(self):
        """Test adding protocol filter."""
        gen = WiresharkFilterGenerator()
        f = gen.add_protocol_filter("http")
        
        assert f is not None
        assert f.filter_text == "http"

    def test_add_beacon_filter(self):
        """Test adding beacon filter."""
        gen = WiresharkFilterGenerator()
        f = gen.add_beacon_filter(
            src_ip="192.168.1.100",
            dst_ip="45.33.32.156",
            dst_port=443,
            interval_seconds=60.0,
        )
        
        assert f is not None
        assert f.category == FilterCategory.BEACON
        assert "ip.src == 192.168.1.100" in f.filter_text
        assert "ip.dst == 45.33.32.156" in f.filter_text
        assert "tcp.dstport == 443" in f.filter_text
        assert f.severity == "high"

    def test_add_dns_tunnel_filter(self):
        """Test adding DNS tunnel filter."""
        gen = WiresharkFilterGenerator()
        f = gen.add_dns_tunnel_filter("suspicious.tk")
        
        assert f is not None
        assert f.category == FilterCategory.DNS_TUNNEL
        assert 'dns.qry.name contains "suspicious.tk"' in f.filter_text

    def test_add_exfiltration_filter(self):
        """Test adding exfiltration filter."""
        gen = WiresharkFilterGenerator()
        f = gen.add_exfiltration_filter(
            src_ip="192.168.1.50",
            dst_ip="185.234.219.10",
            min_bytes=1000,
        )
        
        assert f is not None
        assert f.category == FilterCategory.EXFILTRATION
        assert "ip.src == 192.168.1.50" in f.filter_text
        assert "tcp.len > 1000" in f.filter_text

    def test_add_port_scan_filter(self):
        """Test adding port scan filter."""
        gen = WiresharkFilterGenerator()
        f = gen.add_port_scan_filter(
            scanner_ip="10.0.0.50",
            target_ip="192.168.1.1",
        )
        
        assert f is not None
        assert f.category == FilterCategory.PORT_SCAN
        assert "ip.src == 10.0.0.50" in f.filter_text
        assert "tcp.flags.syn == 1" in f.filter_text
        assert "tcp.flags.ack == 0" in f.filter_text

    def test_add_malicious_ip_filter(self):
        """Test adding malicious IP filter."""
        gen = WiresharkFilterGenerator()
        f = gen.add_malicious_ip_filter(
            ip="185.234.219.10",
            threat_type="C2",
            source="VirusTotal",
        )
        
        assert f is not None
        assert f.category == FilterCategory.MALICIOUS_IP
        assert f.severity == "critical"
        assert "ip.addr == 185.234.219.10" in f.filter_text

    def test_combine_filters_or(self):
        """Test combining filters with OR."""
        gen = WiresharkFilterGenerator()
        f = gen.combine_filters_or(
            filter_texts=[
                "ip.addr == 1.2.3.4",
                "ip.addr == 5.6.7.8",
            ],
            name="Multiple IPs",
            description="Either IP",
        )
        
        assert f is not None
        assert "(ip.addr == 1.2.3.4)" in f.filter_text
        assert "(ip.addr == 5.6.7.8)" in f.filter_text
        assert "||" in f.filter_text

    def test_generate_from_findings(self):
        """Test generating filters from detection findings."""
        gen = WiresharkFilterGenerator()
        
        findings = [
            {
                "detector": "beacon",
                "title": "C2 Beacon",
                "description": "Detected beacon pattern",
                "severity": "high",
                "confidence": 0.85,
                "indicators": {
                    "src_ip": "192.168.1.100",
                    "dst_ip": "45.33.32.156",
                    "dst_port": 443,
                    "interval": 60.0,
                },
            },
            {
                "detector": "dns_tunnel",
                "title": "DNS Tunnel",
                "description": "DNS tunneling detected",
                "severity": "critical",
                "confidence": 0.9,
                "indicators": {
                    "domain": "evil.tk",
                },
            },
        ]
        
        generated = gen.generate_from_findings(findings)
        
        assert len(generated) == 2
        assert any("beacon" in f.category.value for f in generated)
        assert any("dns" in f.category.value for f in generated)

    def test_generate_from_enrichment(self):
        """Test generating filters from enrichment results."""
        gen = WiresharkFilterGenerator()
        
        enrichment_results = [
            {
                "indicator": "185.234.219.10",
                "indicator_type": "ip",
                "threat_level": "malicious",
                "virustotal": {"detections": 10, "total_engines": 90},
                "abuseipdb": {"abuse_confidence_score": 90, "categories": ["Web Attack"]},
            },
            {
                "indicator": "evil-domain.ru",
                "indicator_type": "domain",
                "threat_level": "suspicious",
                "otx": {"pulse_count": 5},
            },
        ]
        
        generated = gen.generate_from_enrichment(enrichment_results)
        
        assert len(generated) == 2
        assert any("185.234.219.10" in f.filter_text for f in generated)
        assert any("evil-domain.ru" in f.filter_text for f in generated)

    def test_to_list(self):
        """Test exporting all filters as list of dicts."""
        gen = WiresharkFilterGenerator()
        gen.add_ip_filter("8.8.8.8")
        gen.add_port_filter(443)
        
        result = gen.to_list()
        
        assert len(result) == 2
        assert all(isinstance(f, dict) for f in result)
        assert all("filter" in f for f in result)

    def test_to_wireshark_file(self):
        """Test exporting as Wireshark filter file format."""
        gen = WiresharkFilterGenerator()
        gen.add_ip_filter("8.8.8.8", name="Google DNS")
        
        content = gen.to_wireshark_file()
        
        assert "NetSpecter" in content
        assert "Google DNS" in content
        assert "ip.addr == 8.8.8.8" in content

    def test_clear(self):
        """Test clearing all filters."""
        gen = WiresharkFilterGenerator()
        gen.add_ip_filter("8.8.8.8")
        gen.add_port_filter(443)
        
        assert len(gen.filters) == 2
        
        gen.clear()
        
        assert len(gen.filters) == 0

    def test_validate_ip(self):
        """Test IP validation helper."""
        assert WiresharkFilterGenerator._validate_ip("192.168.1.1") is True
        assert WiresharkFilterGenerator._validate_ip("0.0.0.0") is True
        assert WiresharkFilterGenerator._validate_ip("255.255.255.255") is True
        assert WiresharkFilterGenerator._validate_ip("invalid") is False
        assert WiresharkFilterGenerator._validate_ip("256.1.1.1") is False
        assert WiresharkFilterGenerator._validate_ip("1.2.3") is False

    def test_validate_domain(self):
        """Test domain validation helper."""
        assert WiresharkFilterGenerator._validate_domain("example.com") is True
        assert WiresharkFilterGenerator._validate_domain("sub.example.com") is True
        assert WiresharkFilterGenerator._validate_domain("example") is True
        assert WiresharkFilterGenerator._validate_domain("invalid domain") is False
        assert WiresharkFilterGenerator._validate_domain("") is False
