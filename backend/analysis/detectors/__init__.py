"""
NetSpecter Detection Engines

Specialized detectors for common attack patterns.
"""

from backend.analysis.detectors.base import BaseDetector, Finding, Severity
from backend.analysis.detectors.beacon import BeaconDetector
from backend.analysis.detectors.dns_tunnel import DNSTunnelDetector
from backend.analysis.detectors.exfiltration import ExfiltrationDetector
from backend.analysis.detectors.port_scan import PortScanDetector

__all__ = [
    "BaseDetector",
    "Finding",
    "Severity",
    "BeaconDetector",
    "DNSTunnelDetector",
    "ExfiltrationDetector",
    "PortScanDetector",
]
