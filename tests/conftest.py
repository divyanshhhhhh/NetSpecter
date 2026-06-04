"""
NetSpecter Test Configuration

Pytest fixtures and configuration for all tests.
"""

import pytest
from pathlib import Path


@pytest.fixture
def temp_pcap_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for test PCAP files."""
    pcap_dir = tmp_path / "pcaps"
    pcap_dir.mkdir()
    return pcap_dir
