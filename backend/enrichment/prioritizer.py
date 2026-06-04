"""
AI-based indicator prioritization for VirusTotal lookups.

This module uses a fast LLM to analyze preliminary enrichment results
from AbuseIPDB and OTX, then selects the most suspicious indicators
for VirusTotal validation. This limits VT API calls to 8-12 max,
reducing enrichment time from ~11 minutes to ~3 minutes.
"""

import json
import logging
from dataclasses import dataclass

from backend.ai.openrouter import get_openrouter_client, LLMError
from backend.enrichment.models import EnrichmentResult, ThreatLevel

logger = logging.getLogger(__name__)


# Maximum indicators to send to VirusTotal (8-12 = 2-3 min at 4/min)
MAX_VT_INDICATORS = 10


@dataclass
class PrioritizedIndicators:
    """Result of indicator prioritization."""

    selected: list[str]  # Indicators to query VirusTotal for
    reasons: dict[str, str]  # Reason for each selection
    skipped_count: int  # Number of indicators skipped


PRIORITIZER_SYSTEM_PROMPT = """You are a cybersecurity analyst assistant that helps prioritize network indicators for further investigation.

Your task is to analyze preliminary threat intelligence results from AbuseIPDB and AlienVault OTX, then select the most suspicious indicators that warrant deeper VirusTotal analysis.

Selection criteria (prioritize indicators that):
1. Have malicious/suspicious verdicts from AbuseIPDB or OTX
2. Are associated with known attack patterns (C2, malware, phishing)
3. Have high abuse confidence scores (>50%)
4. Are flagged in multiple pulse feeds
5. Show characteristics of active threats

Skip indicators that:
- Are clearly benign (Google DNS, Cloudflare, major CDNs)
- Have no suspicious indicators from preliminary analysis
- Are private/internal IP addresses
- Are already confirmed clean

IMPORTANT: You must return ONLY valid JSON, no markdown formatting."""


def _build_prioritization_prompt(
    indicators: list[str],
    preliminary_results: dict[str, EnrichmentResult],
    max_selections: int = MAX_VT_INDICATORS,
) -> str:
    """Build the prompt for indicator prioritization."""
    # Build summary of preliminary findings
    findings = []

    for indicator in indicators:
        result = preliminary_results.get(indicator)
        if not result:
            findings.append(
                {"indicator": indicator, "type": "unknown", "preliminary": "no data"}
            )
            continue

        summary = {
            "indicator": indicator,
            "type": result.indicator_type,
            "threat_level": result.overall_threat_level.value,
            "sources": [],
        }

        # Extract AbuseIPDB data
        if result.abuseipdb:
            source_info = {
                "name": "abuseipdb",
                "verdict": result.abuseipdb.threat_level.value,
                "abuse_score": result.abuseipdb.abuse_confidence_score,
                "total_reports": result.abuseipdb.total_reports,
                "usage_type": result.abuseipdb.usage_type or "",
                "isp": result.abuseipdb.isp or "",
                "is_tor": result.abuseipdb.is_tor_node,
            }
            if result.abuseipdb.category_names:
                source_info["categories"] = result.abuseipdb.category_names[:5]
            summary["sources"].append(source_info)

        # Extract OTX data
        if result.otx:
            source_info = {
                "name": "otx",
                "verdict": result.otx.threat_level.value,
                "pulse_count": result.otx.pulse_count,
            }
            if result.otx.malware_families:
                source_info["malware_families"] = result.otx.malware_families[:5]
            if result.otx.tags:
                source_info["tags"] = result.otx.tags[:5]
            summary["sources"].append(source_info)

        findings.append(summary)

    prompt = f"""Analyze these {len(indicators)} network indicators and their preliminary threat intelligence results.
Select the TOP {max_selections} most suspicious indicators that need VirusTotal validation.

PRELIMINARY FINDINGS:
{json.dumps(findings, indent=2)}

Return your selection as JSON:
{{
    "selected": ["indicator1", "indicator2", ...],
    "reasons": {{
        "indicator1": "brief reason for selection",
        "indicator2": "brief reason for selection"
    }}
}}

Only include indicators from the provided list. Select AT MOST {max_selections} indicators.
Focus on indicators that are most likely to be malicious based on the preliminary data."""

    return prompt


async def prioritize_for_virustotal(
    indicators: list[str],
    preliminary_results: dict[str, EnrichmentResult],
    max_selections: int = MAX_VT_INDICATORS,
) -> PrioritizedIndicators:
    """
    Use AI to prioritize which indicators should be sent to VirusTotal.

    Args:
        indicators: List of all indicators to consider
        preliminary_results: Results from AbuseIPDB and OTX lookups
        max_selections: Maximum indicators to select (default 10)

    Returns:
        PrioritizedIndicators with selected indicators and reasons
    """
    if len(indicators) <= max_selections:
        # If we have few indicators, just query all of them
        logger.info(
            f"Only {len(indicators)} indicators, querying all in VirusTotal"
        )
        return PrioritizedIndicators(
            selected=indicators,
            reasons={ind: "auto-selected (small set)" for ind in indicators},
            skipped_count=0,
        )

    logger.info(
        f"Using AI to prioritize {len(indicators)} indicators for VT (max {max_selections})"
    )

    # Check if any indicators already have suspicious/malicious verdicts
    suspicious_indicators = []
    for indicator in indicators:
        result = preliminary_results.get(indicator)
        if result and result.overall_threat_level in (ThreatLevel.SUSPICIOUS, ThreatLevel.MALICIOUS):
            suspicious_indicators.append(indicator)

    # If we have enough suspicious ones from preliminary, use those directly
    if len(suspicious_indicators) >= max_selections:
        logger.info(
            f"Found {len(suspicious_indicators)} suspicious indicators, selecting top {max_selections}"
        )
        selected = suspicious_indicators[:max_selections]
        return PrioritizedIndicators(
            selected=selected,
            reasons={ind: "marked suspicious by preliminary scan" for ind in selected},
            skipped_count=len(indicators) - len(selected),
        )

    # Use AI for more nuanced selection
    client = get_openrouter_client()
    prompt = _build_prioritization_prompt(
        indicators, preliminary_results, max_selections
    )

    response = await client.quick_analyze(
        prompt=prompt,
        system_prompt=PRIORITIZER_SYSTEM_PROMPT,
        max_tokens=2048,
    )

    if isinstance(response, LLMError):
        logger.error(f"AI prioritization failed: {response.message}")
        # Fallback: return already-suspicious + first few unknowns
        fallback = suspicious_indicators[:max_selections]
        remaining_slots = max_selections - len(fallback)
        for ind in indicators:
            if ind not in fallback and remaining_slots > 0:
                fallback.append(ind)
                remaining_slots -= 1
        return PrioritizedIndicators(
            selected=fallback,
            reasons={ind: "fallback selection (AI unavailable)" for ind in fallback},
            skipped_count=len(indicators) - len(fallback),
        )

    # Parse AI response
    try:
        # Clean response content
        content = response.content.strip()
        # Remove markdown code blocks if present
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
            content = content.strip()

        parsed = json.loads(content)
        selected = parsed.get("selected", [])
        reasons = parsed.get("reasons", {})

        # Validate selections are in original list
        valid_selected = [ind for ind in selected if ind in indicators]

        if not valid_selected:
            raise ValueError("No valid indicators in AI response")

        logger.info(
            f"AI selected {len(valid_selected)} indicators for VirusTotal lookup"
        )

        return PrioritizedIndicators(
            selected=valid_selected[:max_selections],
            reasons=reasons,
            skipped_count=len(indicators) - len(valid_selected[:max_selections]),
        )

    except (json.JSONDecodeError, ValueError, KeyError) as e:
        logger.error(f"Failed to parse AI prioritization response: {e}")
        logger.debug(f"Raw response: {response.content[:500]}")

        # Fallback selection
        fallback = suspicious_indicators[:max_selections]
        remaining = max_selections - len(fallback)
        for ind in indicators:
            if ind not in fallback and remaining > 0:
                fallback.append(ind)
                remaining -= 1

        return PrioritizedIndicators(
            selected=fallback,
            reasons={ind: "fallback selection (parse error)" for ind in fallback},
            skipped_count=len(indicators) - len(fallback),
        )
