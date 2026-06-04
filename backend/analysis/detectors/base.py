"""
NetSpecter Base Detector Interface

Defines the abstract base class and common data models for all detection engines.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from backend.analysis.models import ParseResult


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """
    Security finding from a detector.

    Represents a potential security issue identified during analysis.
    """

    detector: str
    """Name of the detector that generated this finding."""

    severity: Severity
    """Severity level of the finding."""

    confidence: float
    """Confidence score (0.0 - 1.0)."""

    title: str
    """Short description of the finding."""

    description: str
    """Detailed explanation of the finding."""

    affected_ips: list[str] = field(default_factory=list)
    """List of IP addresses involved."""

    affected_flows: list[str] = field(default_factory=list)
    """List of flow identifiers (5-tuple strings)."""

    indicators: dict[str, Any] = field(default_factory=dict)
    """Detector-specific indicator data."""

    timestamp_start: float | None = None
    """Start of the finding timeframe."""

    timestamp_end: float | None = None
    """End of the finding timeframe."""

    mitre_techniques: list[str] = field(default_factory=list)
    """Associated MITRE ATT&CK technique IDs."""

    wireshark_filter: str | None = None
    """Suggested Wireshark display filter for this finding."""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "detector": self.detector,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 3),
            "title": self.title,
            "description": self.description,
            "affected_ips": self.affected_ips,
            "affected_flows": self.affected_flows,
            "indicators": self.indicators,
            "timestamp_start": self.timestamp_start,
            "timestamp_end": self.timestamp_end,
            "timestamp_start_iso": (
                datetime.fromtimestamp(self.timestamp_start).isoformat()
                if self.timestamp_start
                else None
            ),
            "timestamp_end_iso": (
                datetime.fromtimestamp(self.timestamp_end).isoformat()
                if self.timestamp_end
                else None
            ),
            "mitre_techniques": self.mitre_techniques,
            "wireshark_filter": self.wireshark_filter,
        }


class BaseDetector(ABC):
    """
    Abstract base class for all detection engines.

    Subclasses must implement the `detect` method to analyze
    parsed PCAP data and return findings.
    """

    # Detector metadata (override in subclasses)
    name: str = "base"
    description: str = "Base detector"
    version: str = "1.0.0"

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize the detector.

        Args:
            config: Optional configuration dictionary for tuning detection parameters.
        """
        self.config = config or {}
        self._setup()

    def _setup(self) -> None:
        """
        Setup hook for subclasses.

        Override this to initialize detector-specific resources.
        """
        pass

    @abstractmethod
    def detect(self, parse_result: ParseResult) -> list[Finding]:
        """
        Analyze parsed PCAP data and return findings.

        Args:
            parse_result: Parsed PCAP data from the streaming parser.

        Returns:
            List of Finding objects representing detected issues.
        """
        raise NotImplementedError

    def get_config_value(self, key: str, default: Any = None) -> Any:
        """Get a configuration value with optional default."""
        return self.config.get(key, default)

    def create_finding(
        self,
        severity: Severity,
        confidence: float,
        title: str,
        description: str,
        **kwargs: Any,
    ) -> Finding:
        """
        Helper to create a Finding with this detector's name.

        Args:
            severity: Finding severity level.
            confidence: Confidence score (0.0 - 1.0).
            title: Short description.
            description: Detailed explanation.
            **kwargs: Additional Finding fields.

        Returns:
            Finding instance.
        """
        return Finding(
            detector=self.name,
            severity=severity,
            confidence=min(1.0, max(0.0, confidence)),
            title=title,
            description=description,
            **kwargs,
        )


class DetectorRegistry:
    """Registry for managing detection engines."""

    _detectors: dict[str, type[BaseDetector]] = {}

    @classmethod
    def register(cls, detector_class: type[BaseDetector]) -> type[BaseDetector]:
        """Register a detector class."""
        cls._detectors[detector_class.name] = detector_class
        return detector_class

    @classmethod
    def get(cls, name: str) -> type[BaseDetector] | None:
        """Get a detector class by name."""
        return cls._detectors.get(name)

    @classmethod
    def all(cls) -> list[type[BaseDetector]]:
        """Get all registered detector classes."""
        return list(cls._detectors.values())

    @classmethod
    def names(cls) -> list[str]:
        """Get all registered detector names."""
        return list(cls._detectors.keys())
