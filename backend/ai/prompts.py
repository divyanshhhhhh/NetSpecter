"""
NetSpecter LLM Prompt Templates

Structured prompts for each phase of AI-powered analysis.
"""

from dataclasses import dataclass


@dataclass
class PromptTemplates:
    """Collection of prompt templates for different analysis phases."""

    # =========================================================================
    # System Prompts
    # =========================================================================

    SYSTEM_STATS_ANALYST = """You are an expert network security analyst specializing in traffic analysis and threat detection. Your task is to analyze PCAP traffic statistics and identify potential security concerns.

Your analysis should:
1. Focus on security-relevant patterns and anomalies
2. Prioritize findings by severity and confidence
3. Provide clear, actionable insights
4. Avoid false positives by considering benign explanations
5. Use technical but accessible language

When identifying threats, consider:
- C2 (Command & Control) communication patterns
- Data exfiltration indicators
- Lateral movement
- Reconnaissance activities
- Malware communication patterns
- Policy violations

Format your response as structured analysis with clear sections."""

    SYSTEM_DETECTION_ANALYST = """You are a threat intelligence analyst specializing in behavioral analysis and attack pattern recognition. You are analyzing detection findings enriched with threat intelligence data.

Your analysis should:
1. Correlate multiple indicators to identify attack patterns
2. Map findings to MITRE ATT&CK techniques where applicable
3. Assess the likely intent and capabilities of threats
4. Recommend specific response actions
5. Provide confidence assessments for each conclusion

Consider attack chains and how individual findings may be related as part of a larger campaign."""

    SYSTEM_SYNTHESIS = """You are a senior security analyst providing an executive summary of a comprehensive network traffic analysis. Your synthesis should:

1. Prioritize the most critical findings
2. Provide clear risk assessments
3. Recommend immediate actions
4. Identify patterns across multiple findings
5. Be concise but thorough

Your output will be used by security teams to prioritize their response efforts."""

    # =========================================================================
    # Phase 1: Statistical Analysis Prompt
    # =========================================================================

    @staticmethod
    def stats_analysis_prompt(stats_summary: str) -> str:
        """
        Generate prompt for statistical analysis phase.

        Args:
            stats_summary: Formatted traffic statistics summary

        Returns:
            Complete prompt for LLM
        """
        return f"""Analyze the following network traffic statistics from a PCAP capture and identify potential security concerns.

{stats_summary}

## Analysis Required

Please provide:

### 1. Executive Summary
A brief 2-3 sentence overview of the traffic and any immediate concerns.

### 2. Top Security Concerns (ranked by severity)
For each concern, provide:
- **Severity**: Critical/High/Medium/Low
- **Category**: Type of potential threat
- **Description**: What was observed
- **Indicators**: Specific IPs, domains, or patterns
- **Confidence**: How confident you are this is malicious (High/Medium/Low)
- **Rationale**: Why this is concerning

### 3. Notable Patterns
Any other interesting patterns that may warrant investigation but are not necessarily threats.

### 4. Recommended Investigation Steps
Specific Wireshark filters or analysis steps to investigate the concerns.

Focus on actionable findings. If the traffic appears largely benign, say so clearly."""

    # =========================================================================
    # Phase 2: Detection Analysis Prompt
    # =========================================================================

    @staticmethod
    def detection_analysis_prompt(
        detection_findings: str,
        threat_intel: str | None = None,
    ) -> str:
        """
        Generate prompt for detection analysis phase.

        Args:
            detection_findings: Formatted detection findings
            threat_intel: Optional threat intelligence data

        Returns:
            Complete prompt for LLM
        """
        intel_section = ""
        if threat_intel:
            intel_section = f"""
## Threat Intelligence Enrichment

{threat_intel}
"""

        return f"""Analyze the following detection findings from automated network traffic analysis.

{detection_findings}
{intel_section}

## Analysis Required

### 1. Attack Assessment
For each significant finding:
- What type of attack or activity does this represent?
- What malware family or attack tool might be involved?
- What is the likely objective of this activity?

### 2. MITRE ATT&CK Mapping
Map the detected behaviors to relevant MITRE ATT&CK techniques:
- Technique ID and name
- How the detection maps to this technique
- Position in the attack chain (Initial Access, Execution, Persistence, etc.)

### 3. Threat Actor Assessment
- What capabilities are indicated?
- Is this likely automated malware or human-operated?
- Any indicators of sophistication level?

### 4. Correlation Analysis
- How do different findings relate to each other?
- Is there evidence of a coordinated attack chain?
- Timeline of activities

### 5. Immediate Response Recommendations
- What should be blocked or contained?
- What systems need investigation?
- Prioritized action items"""

    # =========================================================================
    # Phase 3: Synthesis Prompt
    # =========================================================================

    @staticmethod
    def synthesis_prompt(
        stats_insights: str,
        detection_insights: str,
        threat_intel_summary: str | None = None,
    ) -> str:
        """
        Generate prompt for final synthesis phase.

        Args:
            stats_insights: Insights from statistical analysis
            detection_insights: Insights from detection analysis
            threat_intel_summary: Summary of threat intel findings

        Returns:
            Complete prompt for LLM
        """
        intel_section = ""
        if threat_intel_summary:
            intel_section = f"""
## Threat Intelligence Summary

{threat_intel_summary}
"""

        return f"""Synthesize the following analysis results into a comprehensive security assessment.

## Statistical Analysis Insights

{stats_insights}

## Detection Analysis Insights

{detection_insights}
{intel_section}

## Synthesis Required

### 1. Executive Summary
A concise summary for leadership (3-5 sentences) covering:
- Overall risk level (Critical/High/Medium/Low)
- Primary threats identified
- Recommended immediate actions

### 2. Consolidated Findings
Merge related findings into coherent incidents:
- Incident name/description
- All related indicators
- Complete attack narrative
- Affected systems

### 3. Risk Assessment Matrix
| Finding | Severity | Confidence | Business Impact | Recommended Action |
|---------|----------|------------|-----------------|-------------------|

### 4. Prioritized Response Plan
Ordered list of actions with:
1. Immediate containment steps
2. Investigation priorities
3. Remediation recommendations
4. Detection improvements

### 5. Indicators of Compromise (IOCs)
List all IOCs in a format suitable for blocking/alerting:
- IP addresses
- Domains
- File hashes (if available)
- Network signatures

### 6. Gaps and Limitations
What couldn't be determined from this analysis?
What additional data would improve the assessment?"""

    # =========================================================================
    # Phase 4: Final Synthesis Prompt (Enhanced)
    # =========================================================================

    @staticmethod
    def final_synthesis_prompt(
        traffic_summary: str,
        detection_findings: str,
        enrichment_results: str,
        stats_ai_insights: str | None = None,
    ) -> str:
        """
        Generate prompt for the final comprehensive synthesis.

        This is the culminating analysis that correlates ALL findings
        from parsing, statistics, detection, and enrichment phases.

        Args:
            traffic_summary: High-level traffic statistics
            detection_findings: All detection engine findings
            enrichment_results: Threat intelligence enrichment results
            stats_ai_insights: Optional AI insights from stats phase

        Returns:
            Complete prompt for final synthesis LLM
        """
        stats_section = ""
        if stats_ai_insights:
            stats_section = f"""
## Previous AI Statistical Analysis

{stats_ai_insights}
"""

        return f"""You are performing the FINAL SYNTHESIS of a comprehensive network traffic security analysis. Your job is to correlate ALL findings into a coherent threat assessment and provide actionable intelligence.

## Traffic Overview

{traffic_summary}

## Automated Detection Findings

{detection_findings}

## Threat Intelligence Enrichment

{enrichment_results}
{stats_section}

# FINAL SYNTHESIS REQUIRED

You must produce a comprehensive, actionable security assessment. Think carefully about how individual findings may be related as part of a coordinated attack.

## 1. EXECUTIVE SUMMARY

Provide a brief (4-6 sentences) executive-level summary:
- **Overall Threat Level**: CRITICAL / HIGH / MEDIUM / LOW / MINIMAL
- **Key Threats Identified**: Main threats in plain language
- **Immediate Actions Required**: 1-2 most urgent actions
- **Confidence Assessment**: How confident are we in these conclusions?

## 2. ATTACK CHAIN ANALYSIS

Identify potential attack chains by correlating related findings:

For EACH potential attack chain identified:
- **Attack Name**: Descriptive name for this attack pattern
- **Kill Chain Stage**: Reconnaissance → Initial Access → Execution → Persistence → C2 → Exfiltration
- **Related Indicators**: List all IPs, domains, ports involved
- **Attack Narrative**: Tell the story of what the attacker appears to be doing
- **MITRE ATT&CK Mapping**: Relevant technique IDs (e.g., T1071.001 - Web Protocols)
- **Confidence**: HIGH / MEDIUM / LOW with justification

## 3. THREAT ACTOR ASSESSMENT

Based on the observed activity:
- **Sophistication Level**: Script kiddie / Automated malware / Targeted attack / APT
- **Likely Objectives**: Data theft / Persistence / Disruption / Financial
- **Tools/Malware Indicators**: Any recognizable patterns
- **Attribution Confidence**: Can we attribute to known threat actors?

## 4. PRIORITIZED FINDINGS TABLE

| Priority | Finding | Severity | Confidence | Affected Systems | Recommended Action |
|----------|---------|----------|------------|------------------|-------------------|
| 1        | ...     | Critical | High       | ...              | Block immediately |
| 2        | ...     | High     | Medium     | ...              | Investigate       |
| ...      | ...     | ...      | ...        | ...              | ...               |

## 5. RESPONSE PLAYBOOK

### Immediate Actions (Next 1 hour)
1. [Specific containment action]
2. [Specific blocking action]
3. ...

### Short-term Actions (Next 24 hours)
1. [Investigation step]
2. [Evidence preservation]
3. ...

### Remediation Actions (Next 7 days)
1. [System hardening]
2. [Detection improvement]
3. ...

## 6. INDICATORS OF COMPROMISE (IOCs)

### Network IOCs
```
# Malicious IPs - BLOCK
[List each IP with threat description]

# Malicious Domains - BLOCK
[List each domain with threat description]

# Suspicious Ports/Protocols
[List unusual ports or protocols observed]
```

### Behavioral IOCs
- [Beacon patterns to detect]
- [DNS anomalies to monitor]
- [Data transfer patterns to alert on]

## 7. WIRESHARK FILTER RECOMMENDATIONS

Provide 3-5 high-priority Wireshark display filters to investigate the most critical findings:

```
# Filter 1: [Description]
[filter expression]

# Filter 2: [Description]
[filter expression]
```

## 8. CONFIDENCE & LIMITATIONS

- **Analysis Confidence**: Overall confidence in this assessment (0-100%)
- **Data Quality Issues**: Any gaps in the PCAP data
- **False Positive Risk**: Findings that might be benign
- **Additional Data Needed**: What would improve this analysis

## 9. CONCLUSION

Final 2-3 sentence verdict on the security posture observed in this traffic capture."""

    # =========================================================================
    # Quick Analysis Prompt (for smaller captures)
    # =========================================================================

    @staticmethod
    def quick_analysis_prompt(stats_summary: str, anomalies: str) -> str:
        """
        Generate a prompt for quick analysis of smaller captures.

        Args:
            stats_summary: Traffic statistics summary
            anomalies: Detected anomalies

        Returns:
            Complete prompt for LLM
        """
        return f"""Perform a quick security analysis of this network traffic capture.

## Traffic Statistics

{stats_summary}

## Detected Anomalies

{anomalies}

## Quick Analysis Required

1. **Overall Assessment**: Is this traffic suspicious? (Yes/No/Uncertain)

2. **Key Concerns**: List top 3 security concerns, if any

3. **Recommended Filters**: Provide Wireshark display filters to investigate concerns

4. **Verdict**: Brief conclusion (1-2 sentences)

Be concise and actionable. If the traffic appears benign, clearly state that."""

    # =========================================================================
    # Beacon Analysis Prompt
    # =========================================================================

    @staticmethod
    def beacon_analysis_prompt(beacon_data: str) -> str:
        """
        Generate prompt for detailed beacon analysis.

        Args:
            beacon_data: Beacon detection data

        Returns:
            Complete prompt for LLM
        """
        return f"""Analyze the following potential C2 beacon activity detected in network traffic.

{beacon_data}

## Beacon Analysis Required

1. **Beacon Confirmation**: Is this likely a C2 beacon or legitimate periodic traffic?

2. **Beacon Characteristics**:
   - Interval pattern
   - Jitter analysis
   - Payload patterns (if available)

3. **C2 Framework Assessment**:
   - Could this be Cobalt Strike? (check interval, jitter)
   - Could this be Metasploit?
   - Could this be custom malware?

4. **Legitimate Alternatives**:
   - Could this be a health check or keepalive?
   - Could this be scheduled synchronization?

5. **Investigation Recommendations**:
   - What to look for in packet payloads
   - Related traffic to examine"""

    # =========================================================================
    # DNS Tunneling Analysis Prompt
    # =========================================================================

    @staticmethod
    def dns_tunnel_analysis_prompt(dns_data: str) -> str:
        """
        Generate prompt for DNS tunneling analysis.

        Args:
            dns_data: DNS anomaly data

        Returns:
            Complete prompt for LLM
        """
        return f"""Analyze the following DNS traffic for potential tunneling or exfiltration.

{dns_data}

## DNS Analysis Required

1. **Tunneling Assessment**: Is this likely DNS tunneling?

2. **Encoding Detection**:
   - Base64 patterns?
   - Base32 patterns?
   - Hex encoding?
   - Custom encoding?

3. **Tunneling Tool Assessment**:
   - Could this be dnscat2?
   - Could this be iodine?
   - Could this be DNSExfiltrator?

4. **Data Exfiltration Assessment**:
   - What type of data might be exfiltrated?
   - Volume estimate

5. **Blocking Recommendations**:
   - Domains to block
   - Detection signatures"""
