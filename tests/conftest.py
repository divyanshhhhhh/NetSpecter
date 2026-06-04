"""
NetSpecter Test Configuration

Pytest fixtures and configuration for all tests.
"""

import pytest
from pathlib import Path


@pytest.fixture
def sample_pcaps_dir() -> Path:
    """Get the sample PCAPs directory."""
    return Path(__file__).parent / "sample_pcaps"


@pytest.fixture
def temp_pcap_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for test PCAP files."""
    pcap_dir = tmp_path / "pcaps"
    pcap_dir.mkdir()
    return pcap_dir
