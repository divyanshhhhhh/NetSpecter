"""
NetSpecter Data Models

Lightweight data structures for packet analysis.
Uses __slots__ for memory efficiency when handling millions of packets.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# =============================================================================
# Enums
# =============================================================================


class Protocol(str, Enum):
    """Network protocol types."""

    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    IGMP = "IGMP"
    OTHER = "OTHER"


class ApplicationProtocol(str, Enum):
    """Application layer protocol types."""

    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    TLS = "TLS"
    SSH = "SSH"
    FTP = "FTP"
    SMTP = "SMTP"
    SMB = "SMB"
    RDP = "RDP"
    DHCP = "DHCP"
    NTP = "NTP"
    UNKNOWN = "UNKNOWN"


class TCPFlags(str, Enum):
    """TCP flag constants."""

    FIN = "FIN"
    SYN = "SYN"
    RST = "RST"
    PSH = "PSH"
    ACK = "ACK"
    URG = "URG"


# =============================================================================
# Packet Summary
# =============================================================================


@dataclass(slots=True)
class PacketSummary:
    """
    Lightweight packet representation.

    Uses __slots__ for memory efficiency - critical when processing
    millions of packets from large PCAP files.
    """

    timestamp: float
    """Unix timestamp of packet capture."""

    src_ip: str
    """Source IP address."""

    dst_ip: str
    """Destination IP address."""

    protocol: Protocol
    """Transport layer protocol (TCP/UDP/ICMP/etc)."""

    src_port: int | None = None
    """Source port (for TCP/UDP)."""

    dst_port: int | None = None
    """Destination port (for TCP/UDP)."""

    length: int = 0
    """Packet length in bytes."""

    payload_length: int = 0
    """Payload length in bytes (excluding headers)."""

    tcp_flags: list[str] = field(default_factory=list)
    """TCP flags if applicable (SYN, ACK, FIN, etc)."""

    app_protocol: ApplicationProtocol = ApplicationProtocol.UNKNOWN
    """Detected application protocol."""

    @property
    def flow_key(self) -> str:
        """Generate 5-tuple flow key for aggregation."""
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.protocol.value}"

    @property
    def conversation_key(self) -> str:
        """Generate bidirectional conversation key."""
        # Sort IPs to ensure same key regardless of direction
        ips = sorted([self.src_ip, self.dst_ip])
        return f"{ips[0]}<->{ips[1]}"

    @property
    def is_internal(self) -> bool:
        """Check if packet is internal-only (both IPs private)."""
        return _is_private_ip(self.src_ip) and _is_private_ip(self.dst_ip)

    @property
    def is_outbound(self) -> bool:
        """Check if packet is outbound (internal source, external dest)."""
        return _is_private_ip(self.src_ip) and not _is_private_ip(self.dst_ip)

    @property
    def is_inbound(self) -> bool:
        """Check if packet is inbound (external source, internal dest)."""
        return not _is_private_ip(self.src_ip) and _is_private_ip(self.dst_ip)


# =============================================================================
# Flow (5-tuple aggregation)
# =============================================================================


@dataclass
class Flow:
    """
    Aggregated connection data based on 5-tuple.

    Represents a unidirectional flow between two endpoints.
    """

    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: Protocol

    packet_count: int = 0
    """Total packets in this flow."""

    byte_count: int = 0
    """Total bytes transferred."""

    payload_bytes: int = 0
    """Total payload bytes (excluding headers)."""

    start_time: float = 0.0
    """First packet timestamp."""

    end_time: float = 0.0
    """Last packet timestamp."""

    timestamps: list[float] = field(default_factory=list)
    """Individual packet timestamps for beacon detection."""

    tcp_flags_seen: set[str] = field(default_factory=set)
    """All TCP flags observed in this flow."""

    app_protocol: ApplicationProtocol = ApplicationProtocol.UNKNOWN
    """Detected application protocol."""

    @property
    def flow_key(self) -> str:
        """5-tuple flow identifier."""
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.protocol.value}"

    @property
    def duration_seconds(self) -> float:
        """Flow duration in seconds."""
        return max(0.0, self.end_time - self.start_time)

    @property
    def packets_per_second(self) -> float:
        """Average packets per second."""
        if self.duration_seconds == 0:
            return 0.0
        return self.packet_count / self.duration_seconds

    @property
    def bytes_per_second(self) -> float:
        """Average bytes per second."""
        if self.duration_seconds == 0:
            return 0.0
        return self.byte_count / self.duration_seconds

    @property
    def is_complete_tcp(self) -> bool:
        """Check if TCP flow has proper handshake."""
        return "SYN" in self.tcp_flags_seen and "ACK" in self.tcp_flags_seen

    @property
    def is_syn_only(self) -> bool:
        """Check if flow is SYN-only (potential scan)."""
        return "SYN" in self.tcp_flags_seen and "ACK" not in self.tcp_flags_seen

    def add_packet(self, packet: PacketSummary) -> None:
        """Update flow statistics with a new packet."""
        self.packet_count += 1
        self.byte_count += packet.length
        self.payload_bytes += packet.payload_length

        if self.start_time == 0.0 or packet.timestamp < self.start_time:
            self.start_time = packet.timestamp

        if packet.timestamp > self.end_time:
            self.end_time = packet.timestamp

        # Store timestamps for beacon detection (limit to prevent memory issues)
        if len(self.timestamps) < 10000:
            self.timestamps.append(packet.timestamp)

        # Track TCP flags
        for flag in packet.tcp_flags:
            self.tcp_flags_seen.add(flag)

        # Update app protocol if detected
        if packet.app_protocol != ApplicationProtocol.UNKNOWN:
            self.app_protocol = packet.app_protocol


# =============================================================================
# Conversation (Bidirectional IP pair)
# =============================================================================


@dataclass
class Conversation:
    """
    Bidirectional traffic between two IP addresses.

    Aggregates all flows between two IPs regardless of ports.
    """

    ip_a: str
    """First IP address (lexicographically smaller)."""

    ip_b: str
    """Second IP address (lexicographically larger)."""

    packets_a_to_b: int = 0
    """Packets from ip_a to ip_b."""

    packets_b_to_a: int = 0
    """Packets from ip_b to ip_a."""

    bytes_a_to_b: int = 0
    """Bytes from ip_a to ip_b."""

    bytes_b_to_a: int = 0
    """Bytes from ip_b to ip_a."""

    start_time: float = 0.0
    end_time: float = 0.0

    protocols: set[Protocol] = field(default_factory=set)
    """Protocols used in this conversation."""

    ports_used: set[int] = field(default_factory=set)
    """All ports used in this conversation."""

    @property
    def conversation_key(self) -> str:
        """Bidirectional conversation identifier."""
        return f"{self.ip_a}<->{self.ip_b}"

    @property
    def total_packets(self) -> int:
        """Total packets in both directions."""
        return self.packets_a_to_b + self.packets_b_to_a

    @property
    def total_bytes(self) -> int:
        """Total bytes in both directions."""
        return self.bytes_a_to_b + self.bytes_b_to_a

    @property
    def byte_ratio(self) -> float:
        """
        Ratio of bytes sent vs received.

        Values > 1 indicate more outbound traffic.
        Useful for exfiltration detection.
        """
        if self.bytes_b_to_a == 0:
            return float("inf") if self.bytes_a_to_b > 0 else 1.0
        return self.bytes_a_to_b / self.bytes_b_to_a

    @property
    def duration_seconds(self) -> float:
        """Conversation duration in seconds."""
        return max(0.0, self.end_time - self.start_time)

    def add_packet(self, packet: PacketSummary) -> None:
        """Update conversation with a new packet."""
        # Determine direction
        if packet.src_ip == self.ip_a:
            self.packets_a_to_b += 1
            self.bytes_a_to_b += packet.length
        else:
            self.packets_b_to_a += 1
            self.bytes_b_to_a += packet.length

        # Update timestamps
        if self.start_time == 0.0 or packet.timestamp < self.start_time:
            self.start_time = packet.timestamp
        if packet.timestamp > self.end_time:
            self.end_time = packet.timestamp

        # Track protocols and ports
        self.protocols.add(packet.protocol)
        if packet.src_port:
            self.ports_used.add(packet.src_port)
        if packet.dst_port:
            self.ports_used.add(packet.dst_port)


# =============================================================================
# DNS Query
# =============================================================================


@dataclass
class DNSQuery:
    """
    DNS query and response information.

    Used for DNS tunneling detection and domain reputation lookups.
    """

    timestamp: float
    """Query timestamp."""

    query_name: str
    """Queried domain name."""

    query_type: str
    """Query type (A, AAAA, TXT, MX, etc)."""

    src_ip: str
    """Source IP making the query."""

    dst_ip: str
    """DNS server IP."""

    response_ips: list[str] = field(default_factory=list)
    """Resolved IP addresses."""

    response_code: str = ""
    """DNS response code (NOERROR, NXDOMAIN, etc)."""

    ttl: int = 0
    """Response TTL."""

    response_size: int = 0
    """Size of DNS response."""

    @property
    def parent_domain(self) -> str:
        """Extract parent domain from query."""
        parts = self.query_name.rstrip(".").split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return self.query_name

    @property
    def subdomain(self) -> str:
        """Extract subdomain portion."""
        parts = self.query_name.rstrip(".").split(".")
        if len(parts) > 2:
            return ".".join(parts[:-2])
        return ""

    @property
    def subdomain_length(self) -> int:
        """Length of subdomain portion."""
        return len(self.subdomain)

    @property
    def is_suspicious_tld(self) -> bool:
        """Check for suspicious TLDs often used in phishing/malware."""
        suspicious_tlds = {".tk", ".xyz", ".top", ".pw", ".cc", ".icu", ".buzz"}
        return any(self.query_name.lower().endswith(tld) for tld in suspicious_tlds)


# =============================================================================
# TLS Information
# =============================================================================


@dataclass
class TLSInfo:
    """
    TLS certificate and handshake information.

    Extracted from TLS Client Hello and Server Certificate messages.
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int

    # Server Name Indication
    sni: str = ""
    """Server Name Indication from Client Hello."""

    # Certificate details
    subject_cn: str = ""
    """Certificate Subject Common Name."""

    issuer_cn: str = ""
    """Certificate Issuer Common Name."""

    not_before: str = ""
    """Certificate validity start date."""

    not_after: str = ""
    """Certificate validity end date."""

    serial_number: str = ""
    """Certificate serial number."""

    # Analysis flags
    is_self_signed: bool = False
    """True if certificate is self-signed."""

    is_expired: bool = False
    """True if certificate has expired."""

    version: str = ""
    """TLS version (TLS 1.2, TLS 1.3, etc)."""

    cipher_suite: str = ""
    """Negotiated cipher suite."""

    ja3_hash: str = ""
    """JA3 fingerprint hash of Client Hello."""

    ja3s_hash: str = ""
    """JA3S fingerprint hash of Server Hello."""

    @property
    def is_suspicious(self) -> bool:
        """Check if certificate has suspicious characteristics."""
        return self.is_self_signed or self.is_expired


# =============================================================================
# Parse Result
# =============================================================================


@dataclass
class ParseResult:
    """
    Complete result of PCAP parsing.

    Contains all extracted data structures and summary statistics.
    """

    # Summary statistics
    total_packets: int = 0
    total_bytes: int = 0
    start_time: float = 0.0
    end_time: float = 0.0

    # Aggregated data
    flows: dict[str, Flow] = field(default_factory=dict)
    """Map of flow_key -> Flow."""

    conversations: dict[str, Conversation] = field(default_factory=dict)
    """Map of conversation_key -> Conversation."""

    dns_queries: list[DNSQuery] = field(default_factory=list)
    """All DNS queries observed."""

    tls_info: list[TLSInfo] = field(default_factory=list)
    """TLS certificate information."""

    # Protocol statistics
    protocol_counts: dict[str, int] = field(default_factory=dict)
    """Count of packets by protocol."""

    app_protocol_counts: dict[str, int] = field(default_factory=dict)
    """Count of packets by application protocol."""

    # IP statistics
    src_ip_counts: dict[str, int] = field(default_factory=dict)
    """Packet count by source IP."""

    dst_ip_counts: dict[str, int] = field(default_factory=dict)
    """Packet count by destination IP."""

    # Port statistics
    dst_port_counts: dict[str, int] = field(default_factory=dict)
    """Packet count by destination port."""

    # Errors
    parse_errors: int = 0
    """Number of packets that failed to parse."""

    @property
    def duration_seconds(self) -> float:
        """Total capture duration in seconds."""
        return max(0.0, self.end_time - self.start_time)

    @property
    def packets_per_second(self) -> float:
        """Average packets per second."""
        if self.duration_seconds == 0:
            return 0.0
        return self.total_packets / self.duration_seconds

    @property
    def unique_src_ips(self) -> int:
        """Number of unique source IPs."""
        return len(self.src_ip_counts)

    @property
    def unique_dst_ips(self) -> int:
        """Number of unique destination IPs."""
        return len(self.dst_ip_counts)

    @property
    def external_ips(self) -> set[str]:
        """Set of all external (non-private) IPs."""
        all_ips = set(self.src_ip_counts.keys()) | set(self.dst_ip_counts.keys())
        return {ip for ip in all_ips if not _is_private_ip(ip)}


# =============================================================================
# Parser Progress
# =============================================================================


@dataclass
class ParserProgress:
    """Progress information for streaming parser."""

    packets_processed: int
    total_packets: int | None
    bytes_processed: int
    progress: float  # 0.0 - 1.0
    current_phase: str


# =============================================================================
# Helper Functions
# =============================================================================


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/internal."""
    if not ip:
        return False

    # Handle IPv6 loopback
    if ip == "::1":
        return True

    # Split IPv4
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False

        # Private ranges
        # 10.0.0.0/8
        if parts[0] == 10:
            return True

        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True

        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True

        # Loopback 127.0.0.0/8
        if parts[0] == 127:
            return True

        # Link-local 169.254.0.0/16
        if parts[0] == 169 and parts[1] == 254:
            return True

        return False

    except (ValueError, IndexError):
        return False


def create_conversation_key(ip1: str, ip2: str) -> str:
    """Create a consistent bidirectional conversation key."""
    sorted_ips = sorted([ip1, ip2])
    return f"{sorted_ips[0]}<->{sorted_ips[1]}"
