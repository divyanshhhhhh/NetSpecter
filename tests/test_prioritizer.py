"""
Tests for the AI-based indicator prioritization module.
"""

import pytest
from unittest.mock import AsyncMock, patch

from backend.enrichment.prioritizer import (
    prioritize_for_virustotal,
    PrioritizedIndicators,
    MAX_VT_INDICATORS,
    _build_prioritization_prompt,
)
from backend.enrichment.models import (
    EnrichmentResult,
    AbuseIPDBResult,
    OTXResult,
    ThreatLevel,
)


class TestPrioritizedIndicators:
    """Test the PrioritizedIndicators dataclass."""

    def test_basic_creation(self):
        """Test basic dataclass creation."""
        result = PrioritizedIndicators(
            selected=["8.8.8.8", "1.1.1.1"],
            reasons={"8.8.8.8": "suspicious", "1.1.1.1": "flagged"},
            skipped_count=5,
        )
        assert len(result.selected) == 2
        assert result.skipped_count == 5
        assert "8.8.8.8" in result.reasons


class TestBuildPrioritizationPrompt:
    """Test the prompt building function."""

    def test_empty_indicators(self):
        """Test with no indicators."""
        prompt = _build_prioritization_prompt([], {})
        assert "0 network indicators" in prompt

    def test_with_indicators(self):
        """Test with some indicators."""
        indicators = ["8.8.8.8", "192.168.1.1"]
        results = {
            "8.8.8.8": EnrichmentResult(
                indicator="8.8.8.8",
                indicator_type="ip",
            )
        }
        prompt = _build_prioritization_prompt(indicators, results, max_selections=5)
        assert "2 network indicators" in prompt
        assert "TOP 5" in prompt
        assert "8.8.8.8" in prompt


class TestPrioritizeForVirusTotal:
    """Test the main prioritization function."""

    @pytest.mark.asyncio
    async def test_small_set_auto_selects_all(self):
        """When indicators < max, all should be selected."""
        indicators = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        results = {}

        prioritized = await prioritize_for_virustotal(
            indicators=indicators,
            preliminary_results=results,
            max_selections=10,
        )

        assert len(prioritized.selected) == 3
        assert prioritized.skipped_count == 0
        for ind in indicators:
            assert ind in prioritized.selected

    @pytest.mark.asyncio
    async def test_suspicious_indicators_prioritized(self):
        """Suspicious indicators should be prioritized without AI."""
        indicators = [f"10.0.0.{i}" for i in range(15)]

        # Mark first 10 as suspicious via AbuseIPDB high score
        results = {}
        for i in range(10):
            result = EnrichmentResult(
                indicator=f"10.0.0.{i}",
                indicator_type="ip",
            )
            result.abuseipdb = AbuseIPDBResult(
                ip_address=f"10.0.0.{i}",
                abuse_confidence_score=70,  # High score = suspicious
                total_reports=5,
            )
            results[f"10.0.0.{i}"] = result

        prioritized = await prioritize_for_virustotal(
            indicators=indicators,
            preliminary_results=results,
            max_selections=8,
        )

        # Should select from the suspicious ones
        assert len(prioritized.selected) == 8
        assert prioritized.skipped_count == 7

    @pytest.mark.asyncio
    async def test_fallback_on_ai_error(self):
        """Test fallback behavior when AI fails."""
        indicators = [f"10.0.0.{i}" for i in range(15)]

        # Create some results with OTX pulses
        results = {}
        for i in range(5):
            result = EnrichmentResult(
                indicator=f"10.0.0.{i}",
                indicator_type="ip",
            )
            result.otx = OTXResult(
                indicator=f"10.0.0.{i}",
                indicator_type="ip",
                pulse_count=3,  # Some pulses = suspicious
            )
            results[f"10.0.0.{i}"] = result

        # Mock the AI client to fail
        with patch(
            "backend.enrichment.prioritizer.get_openrouter_client"
        ) as mock_client:
            from backend.ai.openrouter import LLMError

            mock_instance = AsyncMock()
            mock_instance.quick_analyze.return_value = LLMError(
                error_type="api_error",
                message="API failed",
                status_code=500,
            )
            mock_client.return_value = mock_instance

            prioritized = await prioritize_for_virustotal(
                indicators=indicators,
                preliminary_results=results,
                max_selections=8,
            )

            # Should fall back to suspicious + first few
            assert len(prioritized.selected) == 8
            assert "fallback" in prioritized.reasons[prioritized.selected[0]].lower()


class TestMaxVTIndicators:
    """Test the constant value."""

    def test_max_vt_indicators_reasonable(self):
        """Max should be 8-12 for ~3 min VT wait time."""
        assert 8 <= MAX_VT_INDICATORS <= 12
