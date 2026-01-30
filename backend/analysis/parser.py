"""
NetSpecter Streaming PCAP Parser

Memory-efficient packet parser using dpkt for streaming analysis.
Designed to handle 5GB+ PCAP files without memory issues.
"""

import asyncio
import socket
import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import AsyncGenerator, Callable

import dpkt
import structlog

from backend.analysis.models import (
    ApplicationProtocol,
    Conversation,
    DNSQuery,
    Flow,
    PacketSummary,
    ParseResult,
    ParserProgress,
    Protocol,
    TLSInfo,
    create_conversation_key,
)

logger = structlog.get_logger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Well-known ports for protocol detection
PORT_PROTOCOL_MAP: dict[int, ApplicationProtocol] = {
    20: ApplicationProtocol.FTP,
    21: ApplicationProtocol.FTP,
    22: ApplicationProtocol.SSH,
    23: ApplicationProtocol.UNKNOWN,  # Telnet
    25: ApplicationProtocol.SMTP,
    53: ApplicationProtocol.DNS,
    67: ApplicationProtocol.DHCP,
    68: ApplicationProtocol.DHCP,
    80: ApplicationProtocol.HTTP,
    110: ApplicationProtocol.UNKNOWN,  # POP3
    123: ApplicationProtocol.NTP,
    143: ApplicationProtocol.UNKNOWN,  # IMAP
    443: ApplicationProtocol.HTTPS,
    445: ApplicationProtocol.SMB,
    465: ApplicationProtocol.SMTP,
    587: ApplicationProtocol.SMTP,
    993: ApplicationProtocol.UNKNOWN,  # IMAPS
    995: ApplicationProtocol.UNKNOWN,  # POP3S
    3389: ApplicationProtocol.RDP,
    8080: ApplicationProtocol.HTTP,
    8443: ApplicationProtocol.HTTPS,
}

# TCP flag masks
TCP_FLAG_NAMES = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
}


# =============================================================================
# Main Parser Function
# =============================================================================


async def parse_pcap(
    file_path: Path,
    progress_callback: Callable[[ParserProgress], None] | None = None,
    batch_size: int = 10000,
) -> ParseResult:
    """
    Parse a PCAP file using streaming approach.

    Args:
        file_path: Path to the PCAP/PCAPNG file
        progress_callback: Optional callback for progress updates
        batch_size: Number of packets to process before yielding progress

    Returns:
        ParseResult containing all extracted data

    Raises:
        FileNotFoundError: If PCAP file doesn't exist
        ValueError: If file is not a valid PCAP
    """
    if not file_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    logger.info("pcap_parse_starting", file_path=str(file_path))

    # Get file size for progress calculation
    file_size = file_path.stat().st_size

    # Initialize result containers
    result = ParseResult()

    # Use dicts for efficient aggregation
    flows: dict[str, Flow] = {}
    conversations: dict[str, Conversation] = {}
    dns_queries: list[DNSQuery] = []
    tls_info: list[TLSInfo] = []

    # Counters for statistics
    protocol_counts: Counter[str] = Counter()
    app_protocol_counts: Counter[str] = Counter()
    src_ip_counts: Counter[str] = Counter()
    dst_ip_counts: Counter[str] = Counter()
    dst_port_counts: Counter[int] = Counter()

    packet_count = 0
    bytes_processed = 0
    parse_errors = 0

    # Open and parse file
    try:
        with open(file_path, "rb") as f:
            # Try PCAP format first
            try:
                pcap_reader = dpkt.pcap.Reader(f)
            except ValueError:
                # Try PCAPNG format
                f.seek(0)
                try:
                    pcap_reader = dpkt.pcapng.Reader(f)
                except Exception as e:
                    raise ValueError(f"Unable to parse PCAP file: {e}") from e

            # Process packets
            for timestamp, buf in pcap_reader:
                try:
                    # Parse packet
                    packet = _parse_packet(timestamp, buf)

                    if packet is None:
                        parse_errors += 1
                        continue

                    # Update statistics
                    packet_count += 1
                    bytes_processed += len(buf)

                    # Update timestamps
                    if result.start_time == 0.0 or timestamp < result.start_time:
                        result.start_time = timestamp
                    if timestamp > result.end_time:
                        result.end_time = timestamp

                    # Update counters
                    protocol_counts[packet.protocol.value] += 1
                    app_protocol_counts[packet.app_protocol.value] += 1
                    src_ip_counts[packet.src_ip] += 1
                    dst_ip_counts[packet.dst_ip] += 1

                    if packet.dst_port:
                        dst_port_counts[packet.dst_port] += 1

                    # Aggregate into flows
                    flow_key = packet.flow_key
                    if flow_key not in flows:
                        flows[flow_key] = Flow(
                            src_ip=packet.src_ip,
                            dst_ip=packet.dst_ip,
                            src_port=packet.src_port,
                            dst_port=packet.dst_port,
                            protocol=packet.protocol,
                        )
                    flows[flow_key].add_packet(packet)

                    # Aggregate into conversations
                    conv_key = create_conversation_key(packet.src_ip, packet.dst_ip)
                    if conv_key not in conversations:
                        ips = sorted([packet.src_ip, packet.dst_ip])
                        conversations[conv_key] = Conversation(
                            ip_a=ips[0],
                            ip_b=ips[1],
                        )
                    conversations[conv_key].add_packet(packet)

                    # Extract DNS queries
                    if packet.app_protocol == ApplicationProtocol.DNS:
                        dns_query = _extract_dns(timestamp, buf, packet)
                        if dns_query:
                            dns_queries.append(dns_query)

                    # Extract TLS info (only on port 443 or TLS handshakes)
                    if packet.dst_port == 443 or packet.src_port == 443:
                        tls = _extract_tls(timestamp, buf, packet)
                        if tls:
                            tls_info.append(tls)

                except Exception as e:
                    parse_errors += 1
                    if parse_errors <= 10:  # Only log first 10 errors
                        logger.debug("packet_parse_error", error=str(e))

                # Progress callback
                if progress_callback and packet_count % batch_size == 0:
                    progress = ParserProgress(
                        packets_processed=packet_count,
                        total_packets=None,  # Unknown until complete
                        bytes_processed=bytes_processed,
                        progress=min(0.99, bytes_processed / file_size),
                        current_phase="Parsing packets",
                    )
                    progress_callback(progress)

                    # Yield to event loop
                    await asyncio.sleep(0)

    except Exception as e:
        logger.error("pcap_parse_failed", error=str(e), exc_info=True)
        raise

    # Build final result
    result.total_packets = packet_count
    result.total_bytes = bytes_processed
    result.flows = flows
    result.conversations = conversations
    result.dns_queries = dns_queries
    result.tls_info = tls_info
    result.protocol_counts = dict(protocol_counts)
    result.app_protocol_counts = dict(app_protocol_counts)
    result.src_ip_counts = dict(src_ip_counts)
    result.dst_ip_counts = dict(dst_ip_counts)
    result.dst_port_counts = dict(dst_port_counts)
    result.parse_errors = parse_errors

    # Final progress callback
    if progress_callback:
        progress = ParserProgress(
            packets_processed=packet_count,
            total_packets=packet_count,
            bytes_processed=bytes_processed,
            progress=1.0,
            current_phase="Parsing complete",
        )
        progress_callback(progress)

    logger.info(
        "pcap_parse_complete",
        packets=packet_count,
        bytes=bytes_processed,
        flows=len(flows),
        conversations=len(conversations),
        dns_queries=len(dns_queries),
        errors=parse_errors,
    )

    return result


# =============================================================================
# Packet Parsing Helpers
# =============================================================================


def _parse_packet(timestamp: float, buf: bytes) -> PacketSummary | None:
    """
    Parse a raw packet buffer into a PacketSummary.

    Handles Ethernet, IP, TCP, UDP, and ICMP layers.
    """
    try:
        # Parse Ethernet frame
        eth = dpkt.ethernet.Ethernet(buf)

        # Only process IP packets
        if not isinstance(eth.data, dpkt.ip.IP):
            # Check for IPv6
            if isinstance(eth.data, dpkt.ip6.IP6):
                return _parse_ipv6_packet(timestamp, eth.data)
            return None

        ip = eth.data
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)

        # Determine protocol and extract port info
        protocol = Protocol.OTHER
        src_port: int | None = None
        dst_port: int | None = None
        tcp_flags: list[str] = []
        payload_length = 0
        app_protocol = ApplicationProtocol.UNKNOWN

        if isinstance(ip.data, dpkt.tcp.TCP):
            protocol = Protocol.TCP
            tcp = ip.data
            src_port = tcp.sport
            dst_port = tcp.dport
            tcp_flags = _extract_tcp_flags(tcp.flags)
            payload_length = len(tcp.data)

            # Detect application protocol
            app_protocol = _detect_app_protocol(src_port, dst_port, tcp.data)

        elif isinstance(ip.data, dpkt.udp.UDP):
            protocol = Protocol.UDP
            udp = ip.data
            src_port = udp.sport
            dst_port = udp.dport
            payload_length = len(udp.data)

            # Detect application protocol (DNS, DHCP, etc.)
            app_protocol = _detect_app_protocol(src_port, dst_port, udp.data)

        elif isinstance(ip.data, dpkt.icmp.ICMP):
            protocol = Protocol.ICMP
            payload_length = len(ip.data.data) if hasattr(ip.data, "data") else 0

        elif ip.p == 2:  # IGMP
            protocol = Protocol.IGMP

        return PacketSummary(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            length=len(buf),
            payload_length=payload_length,
            tcp_flags=tcp_flags,
            app_protocol=app_protocol,
        )

    except Exception:
        return None


def _parse_ipv6_packet(timestamp: float, ip6: dpkt.ip6.IP6) -> PacketSummary | None:
    """Parse an IPv6 packet."""
    try:
        src_ip = socket.inet_ntop(socket.AF_INET6, ip6.src)
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip6.dst)

        protocol = Protocol.OTHER
        src_port: int | None = None
        dst_port: int | None = None
        tcp_flags: list[str] = []
        payload_length = 0
        app_protocol = ApplicationProtocol.UNKNOWN

        if isinstance(ip6.data, dpkt.tcp.TCP):
            protocol = Protocol.TCP
            tcp = ip6.data
            src_port = tcp.sport
            dst_port = tcp.dport
            tcp_flags = _extract_tcp_flags(tcp.flags)
            payload_length = len(tcp.data)
            app_protocol = _detect_app_protocol(src_port, dst_port, tcp.data)

        elif isinstance(ip6.data, dpkt.udp.UDP):
            protocol = Protocol.UDP
            udp = ip6.data
            src_port = udp.sport
            dst_port = udp.dport
            payload_length = len(udp.data)
            app_protocol = _detect_app_protocol(src_port, dst_port, udp.data)

        elif isinstance(ip6.data, dpkt.icmp6.ICMP6):
            protocol = Protocol.ICMP

        return PacketSummary(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            length=len(ip6),
            payload_length=payload_length,
            tcp_flags=tcp_flags,
            app_protocol=app_protocol,
        )

    except Exception:
        return None


def _extract_tcp_flags(flags: int) -> list[str]:
    """Extract TCP flag names from flag byte."""
    result = []
    for mask, name in TCP_FLAG_NAMES.items():
        if flags & mask:
            result.append(name)
    return result


def _detect_app_protocol(
    src_port: int | None,
    dst_port: int | None,
    payload: bytes,
) -> ApplicationProtocol:
    """Detect application layer protocol from ports and payload."""
    # Check well-known ports first
    if dst_port and dst_port in PORT_PROTOCOL_MAP:
        return PORT_PROTOCOL_MAP[dst_port]

    if src_port and src_port in PORT_PROTOCOL_MAP:
        return PORT_PROTOCOL_MAP[src_port]

    # Try payload inspection for HTTP
    if payload:
        try:
            # Check for HTTP request
            if payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE"):
                return ApplicationProtocol.HTTP

            # Check for HTTP response
            if payload[:5] == b"HTTP/":
                return ApplicationProtocol.HTTP

            # Check for TLS Client Hello
            if len(payload) > 5 and payload[0] == 0x16:  # TLS handshake
                return ApplicationProtocol.TLS

        except Exception:
            pass

    return ApplicationProtocol.UNKNOWN


# =============================================================================
# DNS Extraction
# =============================================================================


def _extract_dns(
    timestamp: float,
    buf: bytes,
    packet: PacketSummary,
) -> DNSQuery | None:
    """Extract DNS query information from a packet."""
    try:
        eth = dpkt.ethernet.Ethernet(buf)

        if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return None

        ip = eth.data

        if isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            if udp.sport != 53 and udp.dport != 53:
                return None

            dns = dpkt.dns.DNS(udp.data)

            # Extract query name
            if dns.qd:
                query = dns.qd[0]
                query_name = query.name

                # Get query type name
                query_type = _dns_type_to_string(query.type)

                # Extract response IPs (for A/AAAA records)
                response_ips = []
                for rr in dns.an:
                    if rr.type == dpkt.dns.DNS_A:
                        response_ips.append(socket.inet_ntoa(rr.rdata))
                    elif rr.type == dpkt.dns.DNS_AAAA:
                        response_ips.append(
                            socket.inet_ntop(socket.AF_INET6, rr.rdata)
                        )

                # Get response code
                response_code = _dns_rcode_to_string(dns.rcode)

                return DNSQuery(
                    timestamp=timestamp,
                    query_name=query_name,
                    query_type=query_type,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    response_ips=response_ips,
                    response_code=response_code,
                    response_size=len(udp.data),
                )

    except Exception:
        pass

    return None


def _dns_type_to_string(qtype: int) -> str:
    """Convert DNS query type to string."""
    dns_types = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY",
    }
    return dns_types.get(qtype, f"TYPE{qtype}")


def _dns_rcode_to_string(rcode: int) -> str:
    """Convert DNS response code to string."""
    rcodes = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }
    return rcodes.get(rcode, f"RCODE{rcode}")


# =============================================================================
# TLS Extraction
# =============================================================================


def _extract_tls(
    timestamp: float,
    buf: bytes,
    packet: PacketSummary,
) -> TLSInfo | None:
    """Extract TLS information from a packet."""
    try:
        eth = dpkt.ethernet.Ethernet(buf)

        if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return None

        ip = eth.data

        if not isinstance(ip.data, dpkt.tcp.TCP):
            return None

        tcp = ip.data
        payload = tcp.data

        if len(payload) < 6:
            return None

        # Check for TLS record
        if payload[0] != 0x16:  # TLS Handshake
            return None

        # Extract TLS version
        version_major = payload[1]
        version_minor = payload[2]
        version = f"TLS {version_major - 2}.{version_minor}"  # Rough approximation

        # Try to extract SNI from Client Hello
        sni = ""
        if len(payload) > 43:
            sni = _extract_sni(payload)

        if sni or version:
            return TLSInfo(
                timestamp=timestamp,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                dst_port=packet.dst_port or 0,
                sni=sni,
                version=version,
            )

    except Exception:
        pass

    return None


def _extract_sni(payload: bytes) -> str:
    """Extract Server Name Indication from TLS Client Hello."""
    try:
        # Skip TLS record header (5 bytes) and handshake header (4 bytes)
        if len(payload) < 43:
            return ""

        # This is a simplified SNI extraction
        # Full implementation would parse the entire Client Hello structure

        # Look for SNI extension (type 0x0000)
        pos = 43  # Start of extensions in a typical Client Hello

        while pos < len(payload) - 4:
            ext_type = struct.unpack("!H", payload[pos : pos + 2])[0]
            ext_len = struct.unpack("!H", payload[pos + 2 : pos + 4])[0]

            if ext_type == 0:  # Server Name extension
                # Parse SNI list
                if pos + 4 + ext_len <= len(payload):
                    sni_data = payload[pos + 4 : pos + 4 + ext_len]
                    if len(sni_data) > 5:
                        # Skip list length (2) + name type (1) + name length (2)
                        name_len = struct.unpack("!H", sni_data[3:5])[0]
                        if len(sni_data) >= 5 + name_len:
                            return sni_data[5 : 5 + name_len].decode("ascii", errors="ignore")

            pos += 4 + ext_len

    except Exception:
        pass

    return ""


# =============================================================================
# Streaming Generator (Alternative API)
# =============================================================================


async def stream_packets(
    file_path: Path,
    batch_size: int = 10000,
) -> AsyncGenerator[list[PacketSummary], None]:
    """
    Stream packets from a PCAP file in batches.

    Yields batches of PacketSummary objects for incremental processing.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    batch: list[PacketSummary] = []

    with open(file_path, "rb") as f:
        try:
            pcap_reader = dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0)
            pcap_reader = dpkt.pcapng.Reader(f)

        for timestamp, buf in pcap_reader:
            packet = _parse_packet(timestamp, buf)
            if packet:
                batch.append(packet)

                if len(batch) >= batch_size:
                    yield batch
                    batch = []
                    await asyncio.sleep(0)  # Yield to event loop

    # Yield remaining packets
    if batch:
        yield batch
