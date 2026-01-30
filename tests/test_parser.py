"""
Tests for the PCAP parser module.
"""

import pytest
from pathlib import Path

from backend.analysis.models import (
    Protocol,
    ApplicationProtocol,
    PacketSummary,
    Flow,
    Conversation,
    ParseResult,
    ParserProgress,
    _is_private_ip,
    create_conversation_key,
)


class TestPacketSummary:
    """Tests for PacketSummary dataclass."""

    def test_flow_key_generation(self):
        """Test that flow keys are generated correctly."""
        packet = PacketSummary(
            timestamp=1234567890.0,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            protocol=Protocol.TCP,
            src_port=54321,
            dst_port=443,
            length=100,
        )

        assert packet.flow_key == "192.168.1.100:54321->8.8.8.8:443/TCP"

    def test_conversation_key_generation(self):
        """Test that conversation keys are bidirectional."""
        packet1 = PacketSummary(
            timestamp=1234567890.0,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            protocol=Protocol.TCP,
        )
        packet2 = PacketSummary(
            timestamp=1234567891.0,
            src_ip="8.8.8.8",
            dst_ip="192.168.1.100",
            protocol=Protocol.TCP,
        )

        # Same conversation key regardless of direction
        assert packet1.conversation_key == packet2.conversation_key

    def test_is_internal(self):
        """Test internal traffic detection."""
        packet = PacketSummary(
            timestamp=1234567890.0,
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            protocol=Protocol.TCP,
        )
        assert packet.is_internal is True

    def test_is_outbound(self):
        """Test outbound traffic detection."""
        packet = PacketSummary(
            timestamp=1234567890.0,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            protocol=Protocol.TCP,
        )
        assert packet.is_outbound is True
        assert packet.is_inbound is False

    def test_is_inbound(self):
        """Test inbound traffic detection."""
        packet = PacketSummary(
            timestamp=1234567890.0,
            src_ip="8.8.8.8",
            dst_ip="192.168.1.100",
            protocol=Protocol.TCP,
        )
        assert packet.is_inbound is True
        assert packet.is_outbound is False


class TestFlow:
    """Tests for Flow dataclass."""

    def test_flow_add_packet(self):
        """Test adding packets to a flow."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=Protocol.TCP,
        )

        packet1 = PacketSummary(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            protocol=Protocol.TCP,
            src_port=54321,
            dst_port=443,
            length=100,
            payload_length=50,
            tcp_flags=["SYN"],
        )
        packet2 = PacketSummary(
            timestamp=1001.0,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            protocol=Protocol.TCP,
            src_port=54321,
            dst_port=443,
            length=200,
            payload_length=150,
            tcp_flags=["ACK"],
        )

        flow.add_packet(packet1)
        flow.add_packet(packet2)

        assert flow.packet_count == 2
        assert flow.byte_count == 300
        assert flow.payload_bytes == 200
        assert flow.start_time == 1000.0
        assert flow.end_time == 1001.0
        assert "SYN" in flow.tcp_flags_seen
        assert "ACK" in flow.tcp_flags_seen

    def test_flow_duration(self):
        """Test flow duration calculation."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=Protocol.TCP,
            start_time=1000.0,
            end_time=1010.0,
            packet_count=100,
        )

        assert flow.duration_seconds == 10.0
        assert flow.packets_per_second == 10.0

    def test_syn_only_detection(self):
        """Test SYN-only flow detection for scan detection."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=Protocol.TCP,
        )
        flow.tcp_flags_seen = {"SYN"}

        assert flow.is_syn_only is True
        assert flow.is_complete_tcp is False

        flow.tcp_flags_seen.add("ACK")
        assert flow.is_syn_only is False
        assert flow.is_complete_tcp is True


class TestConversation:
    """Tests for Conversation dataclass."""

    def test_conversation_byte_ratio(self):
        """Test byte ratio calculation for exfiltration detection."""
        conv = Conversation(
            ip_a="192.168.1.100",
            ip_b="8.8.8.8",
            bytes_a_to_b=10000,  # Outbound
            bytes_b_to_a=1000,  # Inbound
        )

        assert conv.byte_ratio == 10.0  # 10x more outbound


class TestPrivateIPDetection:
    """Tests for private IP detection."""

    def test_class_a_private(self):
        """Test 10.0.0.0/8 detection."""
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("10.255.255.255") is True

    def test_class_b_private(self):
        """Test 172.16.0.0/12 detection."""
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("172.31.255.255") is True
        assert _is_private_ip("172.15.0.1") is False
        assert _is_private_ip("172.32.0.1") is False

    def test_class_c_private(self):
        """Test 192.168.0.0/16 detection."""
        assert _is_private_ip("192.168.0.1") is True
        assert _is_private_ip("192.168.255.255") is True
        assert _is_private_ip("192.169.0.1") is False

    def test_loopback(self):
        """Test loopback detection."""
        assert _is_private_ip("127.0.0.1") is True
        assert _is_private_ip("127.255.255.255") is True

    def test_public_ips(self):
        """Test public IP detection."""
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("1.1.1.1") is False
        assert _is_private_ip("142.250.185.46") is False


class TestConversationKey:
    """Tests for conversation key generation."""

    def test_conversation_key_is_bidirectional(self):
        """Test that conversation keys are the same regardless of direction."""
        key1 = create_conversation_key("192.168.1.100", "8.8.8.8")
        key2 = create_conversation_key("8.8.8.8", "192.168.1.100")

        assert key1 == key2
