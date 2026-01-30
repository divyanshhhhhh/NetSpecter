"""
NetSpecter Final Synthesis Module

Orchestrates the final AI-powered synthesis of all analysis phases.
Correlates findings from parsing, statistics, detection, and enrichment.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import structlog

from backend.ai.openrouter import get_openrouter_client, LLMResponse, LLMError
from backend.ai.prompts import PromptTemplates
from backend.config import settings

logger = structlog.get_logger(__name__)


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class SynthesisInput:
    """Input data for synthesis from all analysis phases."""
    
    # Traffic summary
    total_packets: int
    total_bytes: int
    duration_seconds: float
    start_time: str
    end_time: str
    unique_ips: int
    total_flows: int
    
    # Detection findings
    findings: list[dict] = field(default_factory=list)
    
    # Enrichment results
    enrichment_results: list[dict] = field(default_factory=list)
    enrichment_stats: dict = field(default_factory=dict)
    
    # Previous AI insights
    stats_ai_content: str | None = None
    
    # Statistics summary
    top_talkers: list[dict] = field(default_factory=list)
    protocol_distribution: dict = field(default_factory=dict)
    port_distribution: dict = field(default_factory=dict)
    anomalies: list[dict] = field(default_factory=list)


@dataclass
class SynthesisResult:
    """Result from the final synthesis phase."""
    
    success: bool
    """Whether synthesis completed successfully."""
    
    content: str
    """The synthesis content (markdown formatted)."""
    
    model: str
    """Model used for synthesis."""
    
    tokens_used: int
    """Total tokens consumed."""
    
    error: str | None = None
    """Error message if synthesis failed."""
    
    executive_summary: str | None = None
    """Extracted executive summary section."""
    
    threat_level: str = "unknown"
    """Extracted overall threat level."""
    
    attack_chains: list[dict] = field(default_factory=list)
    """Extracted attack chains."""
    
    iocs: dict = field(default_factory=dict)
    """Extracted IOCs."""
    
    recommended_filters: list[str] = field(default_factory=list)
    """Wireshark filters recommended by AI."""
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "success": self.success,
            "content": self.content,
            "model": self.model,
            "tokens_used": self.tokens_used,
            "error": self.error,
            "executive_summary": self.executive_summary,
            "threat_level": self.threat_level,
            "attack_chains": self.attack_chains,
            "iocs": self.iocs,
            "recommended_filters": self.recommended_filters,
        }


# =============================================================================
# Context Formatters
# =============================================================================


def format_traffic_summary(input_data: SynthesisInput) -> str:
    """Format traffic overview for the synthesis prompt."""
    lines = [
        f"**Capture Duration**: {input_data.duration_seconds:.1f} seconds",
        f"**Time Range**: {input_data.start_time} to {input_data.end_time}",
        f"**Total Packets**: {input_data.total_packets:,}",
        f"**Total Bytes**: {_format_bytes(input_data.total_bytes)}",
        f"**Unique IPs**: {input_data.unique_ips}",
        f"**Total Flows**: {input_data.total_flows}",
        "",
    ]
    
    if input_data.top_talkers:
        lines.append("### Top Talkers (by bytes)")
        for talker in input_data.top_talkers[:5]:
            ip = talker.get("ip", "unknown")
            bytes_val = talker.get("bytes", 0)
            lines.append(f"- {ip}: {_format_bytes(bytes_val)}")
        lines.append("")
    
    if input_data.protocol_distribution:
        lines.append("### Protocol Distribution")
        for proto, count in sorted(
            input_data.protocol_distribution.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]:
            lines.append(f"- {proto}: {count:,} packets")
        lines.append("")
    
    if input_data.anomalies:
        lines.append(f"### Statistical Anomalies: {len(input_data.anomalies)} detected")
        for anomaly in input_data.anomalies[:5]:
            desc = anomaly.get("description", "Unknown anomaly")
            severity = anomaly.get("severity", "medium")
            lines.append(f"- [{severity.upper()}] {desc}")
        lines.append("")
    
    return "\n".join(lines)


def format_detection_findings(findings: list[dict]) -> str:
    """Format detection findings for the synthesis prompt."""
    if not findings:
        return "No automated detections triggered."
    
    lines = [
        f"**Total Findings**: {len(findings)}",
        "",
    ]
    
    # Group by severity
    severity_groups: dict[str, list[dict]] = {}
    for finding in findings:
        severity = finding.get("severity", "medium").lower()
        if severity not in severity_groups:
            severity_groups[severity] = []
        severity_groups[severity].append(finding)
    
    # Output by severity order
    severity_order = ["critical", "high", "medium", "low", "info"]
    
    for severity in severity_order:
        group = severity_groups.get(severity, [])
        if not group:
            continue
        
        lines.append(f"### {severity.upper()} Severity ({len(group)})")
        lines.append("")
        
        for finding in group:
            title = finding.get("title", "Unknown")
            detector = finding.get("detector", "unknown")
            confidence = finding.get("confidence", 0.5)
            description = finding.get("description", "")[:300]
            
            lines.append(f"**{title}** (detector: {detector}, confidence: {confidence:.0%})")
            lines.append(f"> {description}")
            
            # Include indicators
            indicators = finding.get("indicators", {})
            if indicators:
                indicator_strs = []
                for k, v in list(indicators.items())[:5]:
                    indicator_strs.append(f"{k}={v}")
                lines.append(f"Indicators: {', '.join(indicator_strs)}")
            
            lines.append("")
    
    return "\n".join(lines)


def format_enrichment_results(
    results: list[dict],
    stats: dict,
) -> str:
    """Format enrichment results for the synthesis prompt."""
    if not results:
        return "No threat intelligence enrichment performed (no API keys configured)."
    
    # Extract stats
    total = stats.get("total_enriched", 0)
    malicious = stats.get("malicious_found", 0)
    suspicious = stats.get("suspicious_found", 0)
    
    lines = [
        f"**Indicators Checked**: {total}",
        f"**Malicious**: {malicious}",
        f"**Suspicious**: {suspicious}",
        "",
    ]
    
    # Group by threat level
    malicious_indicators = [r for r in results if r.get("threat_level") == "malicious"]
    suspicious_indicators = [r for r in results if r.get("threat_level") == "suspicious"]
    
    if malicious_indicators:
        lines.append("### MALICIOUS Indicators")
        for ind in malicious_indicators[:10]:
            indicator = ind.get("indicator", "unknown")
            ind_type = ind.get("indicator_type", "unknown")
            
            sources = []
            details = []
            
            vt = ind.get("virustotal", {})
            if vt and not vt.get("error"):
                detections = vt.get("detections", 0)
                total_engines = vt.get("total_engines", 0)
                if detections > 0:
                    sources.append(f"VT: {detections}/{total_engines}")
                    details.append(f"VT detections: {detections}")
            
            abuse = ind.get("abuseipdb", {})
            if abuse and not abuse.get("error"):
                score = abuse.get("abuse_confidence_score", 0)
                if score > 0:
                    sources.append(f"AbuseIPDB: {score}%")
                    categories = abuse.get("categories", [])
                    if categories:
                        details.append(f"Categories: {', '.join(categories[:3])}")
            
            otx = ind.get("otx", {})
            if otx and not otx.get("error"):
                pulses = otx.get("pulse_count", 0)
                if pulses > 0:
                    sources.append(f"OTX: {pulses} pulses")
                    families = otx.get("malware_families", [])
                    if families:
                        details.append(f"Malware: {', '.join(families[:3])}")
            
            lines.append(f"- **{indicator}** ({ind_type})")
            if sources:
                lines.append(f"  Sources: {' | '.join(sources)}")
            if details:
                for d in details:
                    lines.append(f"  - {d}")
        lines.append("")
    
    if suspicious_indicators:
        lines.append("### SUSPICIOUS Indicators")
        for ind in suspicious_indicators[:10]:
            indicator = ind.get("indicator", "unknown")
            ind_type = ind.get("indicator_type", "unknown")
            lines.append(f"- {indicator} ({ind_type})")
        lines.append("")
    
    return "\n".join(lines)


def _format_bytes(bytes_val: int) -> str:
    """Format bytes into human-readable format."""
    if bytes_val >= 1_000_000_000:
        return f"{bytes_val / 1_000_000_000:.2f} GB"
    elif bytes_val >= 1_000_000:
        return f"{bytes_val / 1_000_000:.2f} MB"
    elif bytes_val >= 1_000:
        return f"{bytes_val / 1_000:.2f} KB"
    else:
        return f"{bytes_val} bytes"


# =============================================================================
# Response Parser
# =============================================================================


def parse_synthesis_response(content: str) -> dict:
    """
    Parse structured data from the synthesis response.
    
    Args:
        content: Raw LLM response content
        
    Returns:
        Dictionary with extracted structured data
    """
    result = {
        "executive_summary": None,
        "threat_level": "unknown",
        "attack_chains": [],
        "iocs": {"ips": [], "domains": []},
        "recommended_filters": [],
    }
    
    # Extract executive summary (look for section header)
    if "EXECUTIVE SUMMARY" in content.upper():
        try:
            start = content.upper().find("EXECUTIVE SUMMARY")
            # Find the next section header
            next_section = _find_next_section(content, start + 20)
            if next_section > start:
                summary_text = content[start:next_section].strip()
                # Remove the header itself
                lines = summary_text.split("\n")[1:]
                result["executive_summary"] = "\n".join(lines).strip()[:1000]
        except Exception:
            pass
    
    # Extract threat level
    threat_level_patterns = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]
    content_upper = content.upper()
    for level in threat_level_patterns:
        if f"OVERALL THREAT LEVEL: {level}" in content_upper:
            result["threat_level"] = level.lower()
            break
        if f"**OVERALL THREAT LEVEL**: {level}" in content_upper:
            result["threat_level"] = level.lower()
            break
        if f"THREAT LEVEL: {level}" in content_upper:
            result["threat_level"] = level.lower()
            break
    
    # Extract IOCs - look for IP addresses
    import re
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    found_ips = set(ip_pattern.findall(content))
    # Filter out obviously non-malicious
    for ip in found_ips:
        parts = ip.split(".")
        try:
            if all(0 <= int(p) <= 255 for p in parts):
                # Skip private/local
                first = int(parts[0])
                if first in (10, 127):
                    continue
                if first == 192 and int(parts[1]) == 168:
                    continue
                if first == 172 and 16 <= int(parts[1]) <= 31:
                    continue
                result["iocs"]["ips"].append(ip)
        except ValueError:
            pass
    
    # Limit IOCs
    result["iocs"]["ips"] = result["iocs"]["ips"][:20]
    
    # Extract Wireshark filters
    if "WIRESHARK" in content.upper():
        # Look for filter patterns
        filter_pattern = re.compile(
            r'(?:ip\.addr|ip\.src|ip\.dst|tcp\.port|udp\.port|dns\.qry\.name|frame\.time)'
            r'[^`\n]*',
            re.IGNORECASE
        )
        found_filters = filter_pattern.findall(content)
        result["recommended_filters"] = list(set(found_filters))[:10]
    
    return result


def _find_next_section(content: str, start: int) -> int:
    """Find the start of the next markdown section."""
    # Look for ## headers
    remaining = content[start:]
    
    patterns = ["## ", "### ", "# "]
    min_pos = len(content)
    
    for pattern in patterns:
        pos = remaining.find(pattern)
        if pos > 0:  # Must be after start
            actual_pos = start + pos
            if actual_pos < min_pos:
                min_pos = actual_pos
    
    return min_pos


# =============================================================================
# Synthesis Orchestrator
# =============================================================================


class SynthesisOrchestrator:
    """
    Orchestrates the final synthesis phase.
    
    Collects inputs from all previous phases and runs the final LLM synthesis.
    """
    
    def __init__(self) -> None:
        """Initialize the orchestrator."""
        self._llm_client = get_openrouter_client()
    
    @property
    def is_configured(self) -> bool:
        """Check if synthesis can be performed."""
        return self._llm_client.is_configured
    
    async def synthesize(
        self,
        input_data: SynthesisInput,
    ) -> SynthesisResult:
        """
        Perform the final synthesis.
        
        Args:
            input_data: Input data from all analysis phases
            
        Returns:
            SynthesisResult with the final analysis
        """
        if not self.is_configured:
            return SynthesisResult(
                success=False,
                content="",
                model="none",
                tokens_used=0,
                error="OpenRouter API key not configured",
            )
        
        logger.info(
            "synthesis_starting",
            findings=len(input_data.findings),
            enrichments=len(input_data.enrichment_results),
        )
        
        # Format inputs for the prompt
        traffic_summary = format_traffic_summary(input_data)
        detection_findings = format_detection_findings(input_data.findings)
        enrichment_results = format_enrichment_results(
            input_data.enrichment_results,
            input_data.enrichment_stats,
        )
        
        # Build the prompt
        prompt = PromptTemplates.final_synthesis_prompt(
            traffic_summary=traffic_summary,
            detection_findings=detection_findings,
            enrichment_results=enrichment_results,
            stats_ai_insights=input_data.stats_ai_content,
        )
        
        logger.debug(
            "synthesis_prompt_built",
            prompt_length=len(prompt),
        )
        
        # Call the LLM
        response = await self._llm_client.synthesize_findings(
            prompt=prompt,
            system_prompt=PromptTemplates.SYSTEM_SYNTHESIS,
        )
        
        if isinstance(response, LLMError):
            logger.error(
                "synthesis_failed",
                error_type=response.error_type,
                message=response.message,
            )
            return SynthesisResult(
                success=False,
                content="",
                model="unknown",
                tokens_used=0,
                error=f"{response.error_type}: {response.message}",
            )
        
        # Parse the response for structured data
        parsed = parse_synthesis_response(response.content)
        
        logger.info(
            "synthesis_complete",
            model=response.model,
            tokens=response.usage.get("total_tokens", 0),
            threat_level=parsed["threat_level"],
        )
        
        return SynthesisResult(
            success=True,
            content=response.content,
            model=response.model,
            tokens_used=response.usage.get("total_tokens", 0),
            executive_summary=parsed["executive_summary"],
            threat_level=parsed["threat_level"],
            attack_chains=parsed["attack_chains"],
            iocs=parsed["iocs"],
            recommended_filters=parsed["recommended_filters"],
        )


# =============================================================================
# Factory Function
# =============================================================================


_orchestrator_instance: SynthesisOrchestrator | None = None


def get_synthesis_orchestrator() -> SynthesisOrchestrator:
    """Get the singleton synthesis orchestrator."""
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = SynthesisOrchestrator()
    return _orchestrator_instance
