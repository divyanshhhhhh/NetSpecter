"""
Tests for the Synthesis module.
"""

import pytest

from backend.ai.synthesis import (
    SynthesisInput,
    SynthesisResult,
    format_traffic_summary,
    format_detection_findings,
    format_enrichment_results,
    parse_synthesis_response,
    SynthesisOrchestrator,
)


class TestSynthesisInput:
    """Tests for SynthesisInput dataclass."""

    def test_basic_creation(self):
        """Test creating a basic synthesis input."""
        input_data = SynthesisInput(
            total_packets=1000,
            total_bytes=50000,
            duration_seconds=120.5,
            start_time="2024-01-15T10:00:00",
            end_time="2024-01-15T10:02:00",
            unique_ips=50,
            total_flows=25,
        )
        
        assert input_data.total_packets == 1000
        assert input_data.duration_seconds == 120.5
        assert input_data.unique_ips == 50

    def test_with_findings(self):
        """Test synthesis input with findings."""
        input_data = SynthesisInput(
            total_packets=1000,
            total_bytes=50000,
            duration_seconds=60,
            start_time="2024-01-15T10:00:00",
            end_time="2024-01-15T10:01:00",
            unique_ips=10,
            total_flows=5,
            findings=[
                {"title": "Test Finding", "severity": "high"},
            ],
        )
        
        assert len(input_data.findings) == 1


class TestSynthesisResult:
    """Tests for SynthesisResult dataclass."""

    def test_success_result(self):
        """Test creating a success result."""
        result = SynthesisResult(
            success=True,
            content="Analysis complete",
            model="test-model",
            tokens_used=500,
            threat_level="high",
        )
        
        assert result.success is True
        assert result.threat_level == "high"

    def test_error_result(self):
        """Test creating an error result."""
        result = SynthesisResult(
            success=False,
            content="",
            model="unknown",
            tokens_used=0,
            error="API timeout",
        )
        
        assert result.success is False
        assert result.error == "API timeout"

    def test_to_dict(self):
        """Test converting result to dictionary."""
        result = SynthesisResult(
            success=True,
            content="Test content",
            model="deepseek",
            tokens_used=1000,
            executive_summary="Summary here",
            threat_level="critical",
            iocs={"ips": ["1.2.3.4"]},
        )
        
        d = result.to_dict()
        
        assert d["success"] is True
        assert d["threat_level"] == "critical"
        assert "1.2.3.4" in d["iocs"]["ips"]


class TestFormatTrafficSummary:
    """Tests for traffic summary formatting."""

    def test_basic_formatting(self):
        """Test basic traffic summary formatting."""
        input_data = SynthesisInput(
            total_packets=10000,
            total_bytes=5000000,
            duration_seconds=300.5,
            start_time="2024-01-15T10:00:00",
            end_time="2024-01-15T10:05:00",
            unique_ips=100,
            total_flows=50,
        )
        
        result = format_traffic_summary(input_data)
        
        assert "10,000" in result  # Total packets formatted
        assert "300.5" in result  # Duration
        assert "100" in result  # Unique IPs
        assert "5.00 MB" in result  # Bytes formatted

    def test_with_top_talkers(self):
        """Test formatting with top talkers."""
        input_data = SynthesisInput(
            total_packets=1000,
            total_bytes=50000,
            duration_seconds=60,
            start_time="",
            end_time="",
            unique_ips=10,
            total_flows=5,
            top_talkers=[
                {"ip": "192.168.1.100", "bytes": 25000},
                {"ip": "8.8.8.8", "bytes": 15000},
            ],
        )
        
        result = format_traffic_summary(input_data)
        
        assert "Top Talkers" in result
        assert "192.168.1.100" in result
        assert "8.8.8.8" in result


class TestFormatDetectionFindings:
    """Tests for detection findings formatting."""

    def test_empty_findings(self):
        """Test formatting with no findings."""
        result = format_detection_findings([])
        assert "No automated detections" in result

    def test_with_findings(self):
        """Test formatting detection findings."""
        findings = [
            {
                "title": "C2 Beacon Detected",
                "detector": "beacon",
                "severity": "high",
                "confidence": 0.85,
                "description": "Periodic beacon pattern detected",
                "indicators": {"src_ip": "192.168.1.100", "interval": 60},
            },
            {
                "title": "DNS Tunneling",
                "detector": "dns_tunnel",
                "severity": "critical",
                "confidence": 0.9,
                "description": "Suspicious DNS traffic",
                "indicators": {"domain": "evil.tk"},
            },
        ]
        
        result = format_detection_findings(findings)
        
        assert "Total Findings" in result
        assert "C2 Beacon" in result
        assert "HIGH" in result or "high" in result.lower()
        assert "CRITICAL" in result or "critical" in result.lower()
        assert "85%" in result  # Confidence formatted


class TestFormatEnrichmentResults:
    """Tests for enrichment results formatting."""

    def test_empty_results(self):
        """Test formatting with no results."""
        result = format_enrichment_results([], {})
        assert "No threat intelligence enrichment" in result

    def test_with_results(self):
        """Test formatting enrichment results."""
        results = [
            {
                "indicator": "185.234.219.10",
                "indicator_type": "ip",
                "threat_level": "malicious",
                "virustotal": {"detections": 15, "total_engines": 90},
                "abuseipdb": {"abuse_confidence_score": 95, "categories": ["C2", "Botnet"]},
            },
        ]
        stats = {
            "total_enriched": 5,
            "malicious_found": 1,
            "suspicious_found": 2,
        }
        
        result = format_enrichment_results(results, stats)
        
        assert "Indicators Checked" in result
        assert "MALICIOUS" in result
        assert "185.234.219.10" in result
        assert "VT: 15/90" in result


class TestParseSynthesisResponse:
    """Tests for parsing synthesis responses."""

    def test_extract_threat_level_critical(self):
        """Test extracting critical threat level."""
        content = """
## EXECUTIVE SUMMARY
**Overall Threat Level**: CRITICAL
This is a serious threat.
"""
        result = parse_synthesis_response(content)
        assert result["threat_level"] == "critical"

    def test_extract_threat_level_high(self):
        """Test extracting high threat level."""
        content = "Overall Threat Level: HIGH - Some concerns"
        result = parse_synthesis_response(content)
        assert result["threat_level"] == "high"

    def test_extract_threat_level_low(self):
        """Test extracting low threat level."""
        content = "The **Overall Threat Level**: LOW based on analysis."
        result = parse_synthesis_response(content)
        assert result["threat_level"] == "low"

    def test_extract_ips(self):
        """Test extracting IPs from content."""
        content = """
Block the following IPs:
- 185.234.219.10 (C2 server)
- 45.33.32.156 (malware distribution)
Skip internal: 192.168.1.1
"""
        result = parse_synthesis_response(content)
        
        # Should extract external IPs, not private
        assert "185.234.219.10" in result["iocs"]["ips"]
        assert "45.33.32.156" in result["iocs"]["ips"]
        # Private IPs should be filtered
        assert "192.168.1.1" not in result["iocs"]["ips"]

    def test_extract_wireshark_filters(self):
        """Test extracting Wireshark filters from content."""
        content = """
## WIRESHARK Filter Recommendations

```
ip.addr == 185.234.219.10
dns.qry.name contains "evil.tk"
tcp.port == 4444
```
"""
        result = parse_synthesis_response(content)
        
        # Should extract filter patterns
        assert len(result["recommended_filters"]) >= 1

    def test_extract_executive_summary(self):
        """Test extracting executive summary."""
        content = """
# Analysis Report

## EXECUTIVE SUMMARY

This traffic capture shows evidence of C2 activity.
The threat level is HIGH.
Immediate action is required.

## ATTACK CHAIN ANALYSIS

Details here...
"""
        result = parse_synthesis_response(content)
        
        assert result["executive_summary"] is not None
        assert "C2 activity" in result["executive_summary"]


class TestSynthesisOrchestrator:
    """Tests for SynthesisOrchestrator class."""

    def test_is_configured_no_key(self):
        """Test is_configured when no API key."""
        # The orchestrator should check the underlying client
        orchestrator = SynthesisOrchestrator()
        # Will be False if no OPENROUTER_API_KEY in env
        # This test just verifies the property exists
        assert hasattr(orchestrator, "is_configured")

    @pytest.mark.asyncio
    async def test_synthesize_no_api_key(self):
        """Test synthesis fails gracefully without API key."""
        # Create orchestrator - may or may not have API key
        orchestrator = SynthesisOrchestrator()
        
        if not orchestrator.is_configured:
            input_data = SynthesisInput(
                total_packets=100,
                total_bytes=5000,
                duration_seconds=10,
                start_time="",
                end_time="",
                unique_ips=5,
                total_flows=3,
            )
            
            result = await orchestrator.synthesize(input_data)
            
            assert result.success is False
            assert "not configured" in result.error.lower()
