"""
NetSpecter Wireshark Filter Generator

Generates valid Wireshark display filters from analysis findings.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
import re

import structlog

logger = structlog.get_logger(__name__)


class FilterCategory(Enum):
    """Categories of Wireshark filters."""
    
    BEACON = "beacon"
    DNS_TUNNEL = "dns_tunnel"
    EXFILTRATION = "exfiltration"
    PORT_SCAN = "port_scan"
    MALICIOUS_IP = "malicious_ip"
    SUSPICIOUS_DOMAIN = "suspicious_domain"
    CONVERSATION = "conversation"
    TIME_BOUNDED = "time_bounded"
    PROTOCOL = "protocol"
    CUSTOM = "custom"


@dataclass
class WiresharkFilter:
    """
    A Wireshark display filter with metadata.
    
    Attributes:
        name: Human-readable filter name
        filter_text: The actual Wireshark display filter
        description: What this filter isolates
        category: Filter category
        severity: Severity level (critical, high, medium, low, info)
        confidence: Confidence score 0.0-1.0
        related_finding_id: Optional reference to the finding that generated this
    """
    
    name: str
    filter_text: str
    description: str
    category: FilterCategory
    severity: str = "medium"
    confidence: float = 0.5
    related_finding_id: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "filter": self.filter_text,
            "description": self.description,
            "category": self.category.value,
            "severity": self.severity,
            "confidence": self.confidence,
            "related_finding_id": self.related_finding_id,
        }


class WiresharkFilterGenerator:
    """
    Generates Wireshark display filters from analysis results.
    
    Supports:
    - IP address filters (single, ranges, conversations)
    - Port filters
    - Protocol filters
    - Time range filters
    - DNS query filters
    - Combined filters with logical operators
    """
    
    def __init__(self) -> None:
        """Initialize the filter generator."""
        self._filters: list[WiresharkFilter] = []
        self._generated_expressions: set[str] = set()  # Deduplication
    
    @property
    def filters(self) -> list[WiresharkFilter]:
        """Get all generated filters."""
        return self._filters
    
    def clear(self) -> None:
        """Clear all generated filters."""
        self._filters.clear()
        self._generated_expressions.clear()
    
    # =========================================================================
    # IP Address Filters
    # =========================================================================
    
    def add_ip_filter(
        self,
        ip: str,
        name: str | None = None,
        description: str | None = None,
        direction: str = "any",
        category: FilterCategory = FilterCategory.CUSTOM,
        severity: str = "medium",
        confidence: float = 0.5,
        finding_id: str | None = None,
    ) -> WiresharkFilter | None:
        """
        Add a filter for a specific IP address.
        
        Args:
            ip: IP address to filter
            name: Filter name (auto-generated if not provided)
            description: Filter description
            direction: "src", "dst", or "any"
            category: Filter category
            severity: Severity level
            confidence: Confidence score
            finding_id: Related finding ID
            
        Returns:
            Generated filter or None if duplicate
        """
        if not self._validate_ip(ip):
            logger.warning("invalid_ip_for_filter", ip=ip)
            return None
        
        if direction == "src":
            filter_text = f"ip.src == {ip}"
        elif direction == "dst":
            filter_text = f"ip.dst == {ip}"
        else:
            filter_text = f"ip.addr == {ip}"
        
        if filter_text in self._generated_expressions:
            return None
        
        self._generated_expressions.add(filter_text)
        
        filter_obj = WiresharkFilter(
            name=name or f"IP: {ip}",
            filter_text=filter_text,
            description=description or f"Traffic involving {ip}",
            category=category,
            severity=severity,
            confidence=confidence,
            related_finding_id=finding_id,
        )
        
        self._filters.append(filter_obj)
        return filter_obj
    
    def add_conversation_filter(
        self,
        ip1: str,
        ip2: str,
        port1: int | None = None,
        port2: int | None = None,
        protocol: str | None = None,
        name: str | None = None,
        description: str | None = None,
        category: FilterCategory = FilterCategory.CONVERSATION,
        severity: str = "medium",
        confidence: float = 0.5,
        finding_id: str | None = None,
    ) -> WiresharkFilter | None:
        """
        Add a filter for a conversation between two endpoints.
        
        Args:
            ip1: First IP address
            ip2: Second IP address
            port1: Optional port for first endpoint
            port2: Optional port for second endpoint
            protocol: Optional protocol (tcp, udp)
            name: Filter name
            description: Filter description
            category: Filter category
            severity: Severity level
            confidence: Confidence score
            finding_id: Related finding ID
            
        Returns:
            Generated filter or None if invalid/duplicate
        """
        if not (self._validate_ip(ip1) and self._validate_ip(ip2)):
            return None
        
        parts = [f"ip.addr == {ip1}", f"ip.addr == {ip2}"]
        
        if port1 is not None or port2 is not None:
            port_filter = protocol.lower() if protocol in ("tcp", "udp") else "tcp"
            if port1:
                parts.append(f"{port_filter}.port == {port1}")
            if port2:
                parts.append(f"{port_filter}.port == {port2}")
        
        if protocol and protocol.lower() in ("tcp", "udp", "icmp"):
            parts.append(protocol.lower())
        
        filter_text = " && ".join(parts)
        
        if filter_text in self._generated_expressions:
            return None
        
        self._generated_expressions.add(filter_text)
        
        filter_obj = WiresharkFilter(
            name=name or f"Conversation: {ip1} ↔ {ip2}",
            filter_text=filter_text,
            description=description or f"Traffic between {ip1} and {ip2}",
            category=category,
            severity=severity,
            confidence=confidence,
            related_finding_id=finding_id,
        )
        
        self._filters.append(filter_obj)
        return filter_obj
    
    def add_subnet_filter(
        self,
        subnet: str,
        name: str | None = None,
        description: str | None = None,
        direction: str = "any",
        category: FilterCategory = FilterCategory.CUSTOM,
        severity: str = "medium",
        confidence: float = 0.5,
        finding_id: str | None = None,
    ) -> WiresharkFilter | None:
        """
        Add a filter for a subnet (CIDR notation).
        
        Args:
            subnet: Subnet in CIDR notation (e.g., "192.168.1.0/24")
            name: Filter name
            description: Filter description
            direction: "src", "dst", or "any"
            category: Filter category
            severity: Severity level
            confidence: Confidence score
            finding_id: Related finding ID
            
        Returns:
            Generated filter or None if invalid/duplicate
        """
        if "/" not in subnet:
            return None
        
        ip_part = subnet.split("/")[0]
        if not self._validate_ip(ip_part):
            return None
        
        if direction == "src":
            filter_text = f"ip.src == {subnet}"
        elif direction == "dst":
            filter_text = f"ip.dst == {subnet}"
        else:
            filter_text = f"ip.addr == {subnet}"
        
        if filter_text in self._generated_expressions:
            return None
        
        self._generated_expressions.add(filter_text)
        
        filter_obj = WiresharkFilter(
            name=name or f"Subnet: {subnet}",
            filter_text=filter_text,
            description=description or f"Traffic involving subnet {subnet}",
            category=category,
            severity=severity,
            confidence=confidence,
            related_finding_id=finding_id,
        )
        
        self._filters.append(filter_obj)
        return filter_obj
    
    # =========================================================================
    # Port Filters
    # =========================================================================
    
    def add_port_filter(
        self,
        port: int,
        protocol: str = "tcp",
        direction: str = "any",
        name: str | None = None,
        description: str | None = None,
        category: FilterCategory = FilterCategory.CUSTOM,
        severity: str = "medium",
        confidence: float = 0.5,
        finding_id: str | None = None,
    ) -> WiresharkFilter | None:
        """
        Add a filter for a specific port.
        
        Args:
            port: Port number
            protocol: "tcp" or "udp"
            direction: "src", "dst", or "any"
            name: Filter name
            description: Filter description
            category: Filter category
            severity: Severity level
            confidence: Confidence score
            finding_id: Related finding ID
            
        Returns:
            Generated filter or None if invalid/duplicate
        """
        if not (1 <= port <= 65535):
            return None
        
        proto = protocol.lower()
        if proto not in ("tcp", "udp"):
            proto = "tcp"
        
        if direction == "src":
            filter_text = f"{proto}.srcport == {port}"
        elif direction == "dst":
            filter_text = f"{proto}.dstport == {port}"
        else:
            filter_text = f"{proto}.port == {port}"
        
        if filter_text in self._generated_expressions:
            return None
        
        self._generated_expressions.add(filter_text)
        
        filter_obj = WiresharkFilter(
            name=name or f"Port {port}/{proto.upper()}",
            filter_text=filter_text,
            description=description or f"Traffic on port {port}/{proto.upper()}",
            category=category,
            severity=severity,
            confidence=confidence,
            related_finding_id=finding_id,
        )
        
        self._filters.append(filter_obj)
        return filter_obj
    
    def add_port_range_filter(
        self,
        start_port: int,
        end_port: int,
        protocol: str = "tcp",
        name: str | None = None,
        description: str | None = None,
        category: FilterCategory = FilterCategory.CUSTOM,
        severity: str = "medium",
        confidence: float = 0.5,
        finding_id: str | None = None,
    ) -> WiresharkFilter | None:
        """
        Add a filter for a port range.
        
        Args:
            start_port: Start of port range
            end_port: End of port range
            protocol: "tcp" or "udp"
            name: Filter name
            description: Filter description
            category: Filter category
            severity: Severity level
            confidence: Confidence score
            finding_id: Related finding ID
            
        Returns:
            Generated filter or None if invalid/duplicate
        """
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            return None
        
        if start_port > end_port:
            start_port, end_port = end_port, start_port
        
        proto = protocol.lower()
        if proto not in ("tcp", "udp"):
            proto = "tcp"
        
        filter_text = f"{proto}.port >= {start_port} && {proto}.port <= {end_port}"
        
        if filter_text in self._generated_expressions:
            return None
        
        self._generated_expressions.add(filter_text)
        
        filter_obj = WiresharkFilter(
            name=name or f"Ports {start_port}-{end_port}/{proto.upper()}",
            filter_text=filter_text,
            description=description or f"Traffic on ports {start_port}-{end_port}/{proto.upper()}",
            category=category,
            severity=severity,
            confidence=confidence,
            related_finding_id=finding_id,
        )
        
        self._filters.append(filter_obj)
        return filter_obj
    
    # =========================================================================
    # DNS Filters
    # =========================================================================
    
    def add_dns_query_filter(
        self,
        domain: str,
        exact_match: bool = False,
        name: str | None = None,
        description: str | None = None,
        category: FilterCategory = FilterCategory.SUSPICIOUS_DOMAIN,
        severity: str = "medium",
        confidence: float = 0.5,
        finding_id: str | None = None,
    ) -> WiresharkFilter | None:
        """
        Add a filter for DNS queries for a domain.
        
        Args:
            domain: Domain name to filter
            exact_match: If True, use exact match; if False, use contains
            name: Filter name
            description: Filter description
            category: Filter category
            severity: Severity level
            confidence: Confidence score
            finding_id: Related finding ID
            
        Returns:
            Generated filter or None if invalid/duplicate
        """
        if not domain or not self._validate_domain(domain):
            return None
        
        # Escape quotes in domain name
        safe_domain = domain.replace('"', '\\"')
        
        if exact_match:
            filter_text = f'dns.qry.name == "{safe_domain}"'
        else:
            filter_text = f'dns.qry.name contains "{safe_domain}"'
        
        if filter_text in self._generated_expressions:
            return None
        
        self._generated_expressions.add(filter_text)
        
        filter_obj = WiresharkFilter(
            name=name or f"DNS: {domain}",
            filter_text=filter_text,
            description=description or f"DNS queries for {domain}",
            category=category,
            severity=severity,
            confidence=confidence,
            related_finding_id=finding_id,
        )
        
        self._filters.append(filter_obj)
        return filter_obj
    
    def add_dns_response_filter(
        self,
        domain: str,
        response_ip: str | None = None,
        name: str | None = None,
        description: str | None = None,
        category: FilterCategory = FilterCategory.SUSPICIOUS_DOMAIN,
        severity: str = "medium",
        confidence: float = 0.5,
        finding_id: str | None = None,
    ) -> WiresharkFilter | None:
        """
        Add a filter for DNS responses.
        
        Args:
            domain: Domain name
            response_ip: Optional resolved IP address
            name: Filter name
            description: Filter description
            category: Filter category
            severity: Severity level
            confidence: Confidence score
            finding_id: Related finding ID
            
        Returns:
            Generated filter or None if invalid/duplicate
        """
        safe_domain = domain.replace('"', '\\"')
        
        parts = [f'dns.qry.name contains "{safe_domain}"']
        
        if response_ip and self._validate_ip(response_ip):
            parts.append(f"dns.a == {response_ip}")
        
        filter_text = " && ".join(parts)
        
        if filter_text in self._generated_expressions:
            return None
        
        self._generated_expressions.add(filter_text)
        
        filter_obj = WiresharkFilter(
            name=name or f"DNS Response: {domain}",
            filter_text=filter_text,
            description=description or f"DNS responses for {domain}",
            category=category,
            severity=severity,
            confidence=confidence,
            related_finding_id=finding_id,
        )
        
        self._filters.append(filter_obj)
        return filter_obj
    
    # =========================================================================
    # Time Range Filters
    # =========================================================================
    
    def add_time_range_filter(
        self,
        start_time: datetime | str,
        end_time: datetime | str,
        additional_filter: str | None = None,
        name: str | None = None,
        description: str | None = None,
        category: FilterCategory = FilterCategory.TIME_BOUNDED,
        severity: str = "medium",
        confidence: float = 0.5,
        finding_id: str | None = None,
    ) -> WiresharkFilter | None:
        """
        Add a time-bounded filter.
        
        Args:
            start_time: Start time (datetime or ISO string)
            end_time: End time (datetime or ISO string)
            additional_filter: Optional additional filter to combine
            name: Filter name
            description: Filter description
            category: Filter category
            severity: Severity level
            confidence: Confidence score
            finding_id: Related finding ID
            
        Returns:
            Generated filter or None if invalid/duplicate
        """
        # Format times for Wireshark
        if isinstance(start_time, str):
            try:
                start_time = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            except ValueError:
                return None
        
        if isinstance(end_time, str):
            try:
                end_time = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
            except ValueError:
                return None
        
        # Wireshark time format: "YYYY-MM-DD HH:MM:SS"
        start_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
        end_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
        
        time_filter = f'frame.time >= "{start_str}" && frame.time <= "{end_str}"'
        
        if additional_filter:
            filter_text = f"({additional_filter}) && ({time_filter})"
        else:
            filter_text = time_filter
        
        if filter_text in self._generated_expressions:
            return None
        
        self._generated_expressions.add(filter_text)
        
        filter_obj = WiresharkFilter(
            name=name or f"Time: {start_str} to {end_str}",
            filter_text=filter_text,
            description=description or f"Traffic between {start_str} and {end_str}",
            category=category,
            severity=severity,
            confidence=confidence,
            related_finding_id=finding_id,
        )
        
        self._filters.append(filter_obj)
        return filter_obj
    
    # =========================================================================
    # Protocol Filters
    # =========================================================================
    
    def add_protocol_filter(
        self,
        protocol: str,
        name: str | None = None,
        description: str | None = None,
        category: FilterCategory = FilterCategory.PROTOCOL,
        severity: str = "info",
        confidence: float = 1.0,
        finding_id: str | None = None,
    ) -> WiresharkFilter | None:
        """
        Add a protocol filter.
        
        Args:
            protocol: Protocol name (tcp, udp, icmp, http, https, dns, etc.)
            name: Filter name
            description: Filter description
            category: Filter category
            severity: Severity level
            confidence: Confidence score
            finding_id: Related finding ID
            
        Returns:
            Generated filter or None if invalid/duplicate
        """
        # Map common protocol names to Wireshark filters
        protocol_map = {
            "tcp": "tcp",
            "udp": "udp",
            "icmp": "icmp",
            "http": "http",
            "https": "tls",
            "tls": "tls",
            "dns": "dns",
            "ftp": "ftp",
            "ssh": "ssh",
            "telnet": "telnet",
            "smtp": "smtp",
            "imap": "imap",
            "pop": "pop",
            "smb": "smb",
            "smb2": "smb2",
            "rdp": "rdp",
            "dhcp": "dhcp",
            "arp": "arp",
        }
        
        proto_lower = protocol.lower()
        filter_text = protocol_map.get(proto_lower, proto_lower)
        
        if filter_text in self._generated_expressions:
            return None
        
        self._generated_expressions.add(filter_text)
        
        filter_obj = WiresharkFilter(
            name=name or f"Protocol: {protocol.upper()}",
            filter_text=filter_text,
            description=description or f"All {protocol.upper()} traffic",
            category=category,
            severity=severity,
            confidence=confidence,
            related_finding_id=finding_id,
        )
        
        self._filters.append(filter_obj)
        return filter_obj
    
    # =========================================================================
    # Detection-Specific Filters
    # =========================================================================
    
    def add_beacon_filter(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
        protocol: str = "tcp",
        interval_seconds: float | None = None,
        name: str | None = None,
        description: str | None = None,
        confidence: float = 0.7,
        finding_id: str | None = None,
    ) -> WiresharkFilter | None:
        """
        Add a filter for beacon/C2 traffic.
        
        Args:
            src_ip: Source IP (beacon origin)
            dst_ip: Destination IP (C2 server)
            dst_port: Optional destination port
            protocol: Protocol (tcp/udp)
            interval_seconds: Optional beacon interval for description
            name: Filter name
            description: Filter description
            confidence: Confidence score
            finding_id: Related finding ID
            
        Returns:
            Generated filter or None if invalid/duplicate
        """
        if not (self._validate_ip(src_ip) and self._validate_ip(dst_ip)):
            return None
        
        parts = [f"ip.src == {src_ip}", f"ip.dst == {dst_ip}"]
        
        if dst_port:
            proto = protocol.lower() if protocol.lower() in ("tcp", "udp") else "tcp"
            parts.append(f"{proto}.dstport == {dst_port}")
        
        filter_text = " && ".join(parts)
        
        if filter_text in self._generated_expressions:
            return None
        
        self._generated_expressions.add(filter_text)
        
        interval_info = f" (interval: ~{interval_seconds:.1f}s)" if interval_seconds else ""
        
        filter_obj = WiresharkFilter(
            name=name or f"Beacon: {src_ip} → {dst_ip}:{dst_port or '*'}",
            filter_text=filter_text,
            description=description or f"Potential C2 beacon traffic{interval_info}",
            category=FilterCategory.BEACON,
            severity="high",
            confidence=confidence,
            related_finding_id=finding_id,
        )
        
        self._filters.append(filter_obj)
        return filter_obj
    
    def add_dns_tunnel_filter(
        self,
        domain: str,
        name: str | None = None,
        description: str | None = None,
        confidence: float = 0.7,
        finding_id: str | None = None,
    ) -> WiresharkFilter | None:
        """
        Add a filter for DNS tunneling traffic.
        
        Args:
            domain: Base domain used for tunneling
            name: Filter name
            description: Filter description
            confidence: Confidence score
            finding_id: Related finding ID
            
        Returns:
            Generated filter or None if invalid/duplicate
        """
        safe_domain = domain.replace('"', '\\"')
        filter_text = f'dns.qry.name contains "{safe_domain}"'
        
        if filter_text in self._generated_expressions:
            return None
        
        self._generated_expressions.add(filter_text)
        
        filter_obj = WiresharkFilter(
            name=name or f"DNS Tunnel: {domain}",
            filter_text=filter_text,
            description=description or f"DNS tunneling via {domain}",
            category=FilterCategory.DNS_TUNNEL,
            severity="high",
            confidence=confidence,
            related_finding_id=finding_id,
        )
        
        self._filters.append(filter_obj)
        return filter_obj
    
    def add_exfiltration_filter(
        self,
        src_ip: str,
        dst_ip: str,
        min_bytes: int | None = None,
        name: str | None = None,
        description: str | None = None,
        confidence: float = 0.6,
        finding_id: str | None = None,
    ) -> WiresharkFilter | None:
        """
        Add a filter for potential data exfiltration.
        
        Args:
            src_ip: Source IP (internal)
            dst_ip: Destination IP (external)
            min_bytes: Optional minimum payload size filter
            name: Filter name
            description: Filter description
            confidence: Confidence score
            finding_id: Related finding ID
            
        Returns:
            Generated filter or None if invalid/duplicate
        """
        if not (self._validate_ip(src_ip) and self._validate_ip(dst_ip)):
            return None
        
        parts = [f"ip.src == {src_ip}", f"ip.dst == {dst_ip}"]
        
        if min_bytes and min_bytes > 0:
            parts.append(f"tcp.len > {min_bytes}")
        
        filter_text = " && ".join(parts)
        
        if filter_text in self._generated_expressions:
            return None
        
        self._generated_expressions.add(filter_text)
        
        filter_obj = WiresharkFilter(
            name=name or f"Exfiltration: {src_ip} → {dst_ip}",
            filter_text=filter_text,
            description=description or f"Potential data exfiltration to {dst_ip}",
            category=FilterCategory.EXFILTRATION,
            severity="high",
            confidence=confidence,
            related_finding_id=finding_id,
        )
        
        self._filters.append(filter_obj)
        return filter_obj
    
    def add_port_scan_filter(
        self,
        scanner_ip: str,
        target_ip: str | None = None,
        name: str | None = None,
        description: str | None = None,
        confidence: float = 0.8,
        finding_id: str | None = None,
    ) -> WiresharkFilter | None:
        """
        Add a filter for port scanning activity.
        
        Args:
            scanner_ip: IP performing the scan
            target_ip: Optional target IP
            name: Filter name
            description: Filter description
            confidence: Confidence score
            finding_id: Related finding ID
            
        Returns:
            Generated filter or None if invalid/duplicate
        """
        if not self._validate_ip(scanner_ip):
            return None
        
        # SYN packets without ACK flag = connection initiation
        parts = [f"ip.src == {scanner_ip}", "tcp.flags.syn == 1", "tcp.flags.ack == 0"]
        
        if target_ip and self._validate_ip(target_ip):
            parts.insert(1, f"ip.dst == {target_ip}")
        
        filter_text = " && ".join(parts)
        
        if filter_text in self._generated_expressions:
            return None
        
        self._generated_expressions.add(filter_text)
        
        target_info = f" → {target_ip}" if target_ip else ""
        
        filter_obj = WiresharkFilter(
            name=name or f"Port Scan: {scanner_ip}{target_info}",
            filter_text=filter_text,
            description=description or f"SYN scan traffic from {scanner_ip}",
            category=FilterCategory.PORT_SCAN,
            severity="medium",
            confidence=confidence,
            related_finding_id=finding_id,
        )
        
        self._filters.append(filter_obj)
        return filter_obj
    
    def add_malicious_ip_filter(
        self,
        ip: str,
        threat_type: str | None = None,
        source: str | None = None,
        name: str | None = None,
        description: str | None = None,
        confidence: float = 0.9,
        finding_id: str | None = None,
    ) -> WiresharkFilter | None:
        """
        Add a filter for traffic to/from a malicious IP.
        
        Args:
            ip: Malicious IP address
            threat_type: Type of threat (e.g., "C2", "malware", "botnet")
            source: Intelligence source (e.g., "VirusTotal", "AbuseIPDB")
            name: Filter name
            description: Filter description
            confidence: Confidence score
            finding_id: Related finding ID
            
        Returns:
            Generated filter or None if invalid/duplicate
        """
        if not self._validate_ip(ip):
            return None
        
        filter_text = f"ip.addr == {ip}"
        
        if filter_text in self._generated_expressions:
            return None
        
        self._generated_expressions.add(filter_text)
        
        threat_info = f" ({threat_type})" if threat_type else ""
        source_info = f" [via {source}]" if source else ""
        
        filter_obj = WiresharkFilter(
            name=name or f"Malicious: {ip}{threat_info}",
            filter_text=filter_text,
            description=description or f"Traffic involving malicious IP {ip}{source_info}",
            category=FilterCategory.MALICIOUS_IP,
            severity="critical",
            confidence=confidence,
            related_finding_id=finding_id,
        )
        
        self._filters.append(filter_obj)
        return filter_obj
    
    # =========================================================================
    # Combined/Complex Filters
    # =========================================================================
    
    def combine_filters_or(
        self,
        filter_texts: list[str],
        name: str,
        description: str,
        category: FilterCategory = FilterCategory.CUSTOM,
        severity: str = "medium",
        confidence: float = 0.5,
        finding_id: str | None = None,
    ) -> WiresharkFilter | None:
        """
        Combine multiple filters with OR logic.
        
        Args:
            filter_texts: List of filter expressions to combine
            name: Filter name
            description: Filter description
            category: Filter category
            severity: Severity level
            confidence: Confidence score
            finding_id: Related finding ID
            
        Returns:
            Generated filter or None if invalid/duplicate
        """
        if not filter_texts:
            return None
        
        if len(filter_texts) == 1:
            filter_text = filter_texts[0]
        else:
            # Wrap each filter in parentheses and join with OR
            wrapped = [f"({f})" for f in filter_texts]
            filter_text = " || ".join(wrapped)
        
        if filter_text in self._generated_expressions:
            return None
        
        self._generated_expressions.add(filter_text)
        
        filter_obj = WiresharkFilter(
            name=name,
            filter_text=filter_text,
            description=description,
            category=category,
            severity=severity,
            confidence=confidence,
            related_finding_id=finding_id,
        )
        
        self._filters.append(filter_obj)
        return filter_obj
    
    def add_raw_filter(
        self,
        filter_text: str,
        name: str,
        description: str,
        category: FilterCategory = FilterCategory.CUSTOM,
        severity: str = "medium",
        confidence: float = 0.5,
        finding_id: str | None = None,
    ) -> WiresharkFilter | None:
        """
        Add a raw Wireshark filter expression.
        
        Args:
            filter_text: Raw Wireshark display filter
            name: Filter name
            description: Filter description
            category: Filter category
            severity: Severity level
            confidence: Confidence score
            finding_id: Related finding ID
            
        Returns:
            Generated filter or None if duplicate
        """
        if not filter_text or filter_text in self._generated_expressions:
            return None
        
        self._generated_expressions.add(filter_text)
        
        filter_obj = WiresharkFilter(
            name=name,
            filter_text=filter_text,
            description=description,
            category=category,
            severity=severity,
            confidence=confidence,
            related_finding_id=finding_id,
        )
        
        self._filters.append(filter_obj)
        return filter_obj
    
    # =========================================================================
    # Bulk Generation
    # =========================================================================
    
    def generate_from_findings(
        self,
        findings: list[dict],
    ) -> list[WiresharkFilter]:
        """
        Generate filters from detection findings.
        
        Args:
            findings: List of detection finding dictionaries
            
        Returns:
            List of generated filters
        """
        generated = []
        
        for finding in findings:
            detector = finding.get("detector", "").lower()
            indicators = finding.get("indicators", {})
            severity = finding.get("severity", "medium")
            confidence = finding.get("confidence", 0.5)
            finding_id = finding.get("id")
            
            # Use existing wireshark_filter if provided
            if finding.get("wireshark_filter"):
                f = self.add_raw_filter(
                    filter_text=finding["wireshark_filter"],
                    name=finding.get("title", "Detection Finding"),
                    description=finding.get("description", "")[:200],
                    category=self._category_from_detector(detector),
                    severity=severity,
                    confidence=confidence,
                    finding_id=finding_id,
                )
                if f:
                    generated.append(f)
                continue
            
            # Generate based on detector type
            if detector == "beacon":
                src_ip = indicators.get("src_ip")
                dst_ip = indicators.get("dst_ip")
                dst_port = indicators.get("dst_port")
                interval = indicators.get("interval")
                
                if src_ip and dst_ip:
                    f = self.add_beacon_filter(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        interval_seconds=interval,
                        confidence=confidence,
                        finding_id=finding_id,
                    )
                    if f:
                        generated.append(f)
            
            elif detector == "dns_tunnel":
                domain = indicators.get("domain")
                if domain:
                    f = self.add_dns_tunnel_filter(
                        domain=domain,
                        confidence=confidence,
                        finding_id=finding_id,
                    )
                    if f:
                        generated.append(f)
            
            elif detector == "exfiltration":
                src_ip = indicators.get("src_ip")
                dst_ip = indicators.get("dst_ip")
                
                if src_ip and dst_ip:
                    f = self.add_exfiltration_filter(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        confidence=confidence,
                        finding_id=finding_id,
                    )
                    if f:
                        generated.append(f)
            
            elif detector == "port_scan":
                scanner_ip = indicators.get("scanner_ip") or indicators.get("src_ip")
                target_ip = indicators.get("target_ip") or indicators.get("dst_ip")
                
                if scanner_ip:
                    f = self.add_port_scan_filter(
                        scanner_ip=scanner_ip,
                        target_ip=target_ip,
                        confidence=confidence,
                        finding_id=finding_id,
                    )
                    if f:
                        generated.append(f)
        
        return generated
    
    def generate_from_enrichment(
        self,
        enrichment_results: list[dict],
    ) -> list[WiresharkFilter]:
        """
        Generate filters from enrichment results.
        
        Args:
            enrichment_results: List of enrichment result dictionaries
            
        Returns:
            List of generated filters
        """
        generated = []
        
        for result in enrichment_results:
            indicator = result.get("indicator", "")
            indicator_type = result.get("indicator_type", "")
            threat_level = result.get("threat_level", "unknown")
            
            # Only generate for malicious or suspicious
            if threat_level not in ("malicious", "suspicious"):
                continue
            
            sources = []
            threat_types = []
            confidence = 0.5
            
            # Extract threat info from sources
            vt = result.get("virustotal")
            if vt:
                detections = vt.get("detections", 0)
                if detections > 0:
                    sources.append("VirusTotal")
                    confidence = max(confidence, 0.8 if detections > 5 else 0.6)
            
            abuse = result.get("abuseipdb")
            if abuse:
                score = abuse.get("abuse_confidence_score", 0)
                if score > 50:
                    sources.append("AbuseIPDB")
                    categories = abuse.get("categories", [])
                    if categories:
                        threat_types.extend(categories[:3])
                    confidence = max(confidence, score / 100)
            
            otx = result.get("otx")
            if otx:
                pulses = otx.get("pulse_count", 0)
                if pulses > 0:
                    sources.append("OTX")
                    families = otx.get("malware_families", [])
                    if families:
                        threat_types.extend(families[:2])
                    confidence = max(confidence, 0.7 if pulses > 5 else 0.5)
            
            if indicator_type == "ip" and self._validate_ip(indicator):
                f = self.add_malicious_ip_filter(
                    ip=indicator,
                    threat_type=", ".join(threat_types[:2]) if threat_types else None,
                    source=", ".join(sources) if sources else None,
                    confidence=confidence,
                )
                if f:
                    generated.append(f)
            
            elif indicator_type == "domain":
                category = FilterCategory.SUSPICIOUS_DOMAIN
                severity = "critical" if threat_level == "malicious" else "high"
                
                f = self.add_dns_query_filter(
                    domain=indicator,
                    exact_match=False,
                    category=category,
                    severity=severity,
                    confidence=confidence,
                )
                if f:
                    generated.append(f)
        
        return generated
    
    def to_list(self) -> list[dict]:
        """Export all filters as a list of dictionaries."""
        return [f.to_dict() for f in self._filters]
    
    def to_wireshark_file(self) -> str:
        """
        Export filters in a format suitable for Wireshark filter file.
        
        Returns:
            String content for a Wireshark filter file
        """
        lines = ["# NetSpecter Generated Filters", ""]
        
        for f in self._filters:
            # Comment with name and description
            lines.append(f"# {f.name}")
            lines.append(f"# {f.description}")
            lines.append(f'"{f.name}" {f.filter_text}')
            lines.append("")
        
        return "\n".join(lines)
    
    # =========================================================================
    # Validation Helpers
    # =========================================================================
    
    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """Validate IPv4 address format."""
        if not ip:
            return False
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            for part in parts:
                num = int(part)
                if not (0 <= num <= 255):
                    return False
            return True
        except (ValueError, AttributeError):
            return False
    
    @staticmethod
    def _validate_domain(domain: str) -> bool:
        """Basic domain name validation."""
        if not domain:
            return False
        # Basic check: contains at least one dot, no spaces
        if " " in domain:
            return False
        if len(domain) > 253:
            return False
        # Should have valid characters
        pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')
        return bool(pattern.match(domain))
    
    @staticmethod
    def _category_from_detector(detector: str) -> FilterCategory:
        """Map detector name to filter category."""
        mapping = {
            "beacon": FilterCategory.BEACON,
            "dns_tunnel": FilterCategory.DNS_TUNNEL,
            "exfiltration": FilterCategory.EXFILTRATION,
            "port_scan": FilterCategory.PORT_SCAN,
        }
        return mapping.get(detector.lower(), FilterCategory.CUSTOM)
