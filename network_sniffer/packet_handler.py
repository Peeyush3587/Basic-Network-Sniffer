"""Packet parsing, protocol resolution, and formatting functions.

This module provides helper utilities to inspect Scapy packets, extract Layer 3
and Layer 4 protocol metadata, format hex/ASCII payload dumps, and produce
readable summaries and detail blocks.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from colorama import Fore, Style
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import Packet, Raw

# Common IP Protocol Number -> Protocol Name mapping
IP_PROTOCOL_MAP: Dict[int, str] = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-Encap",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}

# TCP Flag definitions (flag character -> human-readable description)
TCP_FLAG_MAP: Dict[str, str] = {
    "F": "FIN (Finish)",
    "S": "SYN (Synchronize)",
    "R": "RST (Reset)",
    "P": "PSH (Push)",
    "A": "ACK (Acknowledge)",
    "U": "URG (Urgent)",
    "E": "ECE (ECN-Echo)",
    "C": "CWR (Congestion Window Reduced)",
}


@dataclass
class PacketStats:
    """Statistics counter for captured packets."""

    total_packets: int = 0
    parse_errors: int = 0
    protocol_counts: Dict[str, int] = field(
        default_factory=lambda: {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
    )

    def record_packet(self, protocol_category: str) -> None:
        """Increment counters for the given protocol category."""
        self.total_packets += 1
        key = protocol_category if protocol_category in self.protocol_counts else "Other"
        self.protocol_counts[key] += 1


@dataclass
class ParsedPacketInfo:
    """Normalized packet metadata for display and analysis."""

    timestamp: str
    src_ip: str
    dst_ip: str
    protocol_name: str
    protocol_category: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags_str: Optional[str] = None
    tcp_flags_expanded: Optional[List[str]] = None
    payload_len: int = 0
    payload_bytes: bytes = b""


PROTO_COLORS: Dict[str, str] = {
    "TCP": Fore.BLUE,
    "UDP": Fore.GREEN,
    "ICMP": Fore.YELLOW,
}


def get_protocol_color(protocol_category: str) -> str:
    """Return the Colorama color associated with a protocol category."""
    return PROTO_COLORS.get(protocol_category.upper(), Fore.WHITE)


def format_hex_ascii_dump(data: bytes, max_bytes: int = 64) -> str:
    """Format byte data as an educational hex + ASCII side-by-side dump.

    Each row prints up to 16 bytes:
    - 4-digit hex offset
    - Hex bytes separated by spaces with an extra space after 8 bytes
    - ASCII representation (printable characters as-is, non-printable as '.')

    Args:
        data: Raw payload bytes to display.
        max_bytes: Maximum number of bytes to include in the dump (default: 64).

    Returns:
        A multiline string representing the hexdump.
    """
    if not data:
        return "       (No payload data)"

    slice_data = data[:max_bytes]
    lines: List[str] = []

    for offset in range(0, len(slice_data), 16):
        chunk = slice_data[offset : offset + 16]
        hex_parts = [f"{b:02x}" for b in chunk]
        hex_str = (
            f"{' '.join(hex_parts[:8])}  {' '.join(hex_parts[8:])}"
            if len(hex_parts) > 8
            else " ".join(hex_parts)
        )
        ascii_chars = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"       {offset:04x}  {hex_str.ljust(49)} |{ascii_chars}|")

    if len(data) > max_bytes:
        lines.append(f"       ... [{len(data) - max_bytes} additional bytes omitted]")

    return "\n".join(lines)


def parse_tcp_flags(tcp_layer: TCP) -> Tuple[str, List[str]]:
    """Extract and decode TCP flags from a TCP layer.

    Args:
        tcp_layer: Scapy TCP layer object.

    Returns:
        A tuple of (flag_characters, list_of_expanded_names).
    """
    flags_val = str(tcp_layer.flags)
    expanded = [TCP_FLAG_MAP.get(c, f"Flag({c})") for c in flags_val]
    return flags_val, expanded


def parse_packet(packet: Packet) -> ParsedPacketInfo:
    """Parse a Scapy packet into a structured ParsedPacketInfo instance.

    Args:
        packet: Scapy Packet object.

    Returns:
        Populated ParsedPacketInfo object.
    """
    # Timestamp extraction
    try:
        dt = datetime.datetime.fromtimestamp(float(packet.time))
    except (AttributeError, TypeError, ValueError, OSError):
        dt = datetime.datetime.now()
    timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")

    # Layer 3 / Network Layer resolution
    src_ip = "Unknown"
    dst_ip = "Unknown"
    protocol_name = "Unknown"
    protocol_category = "Other"

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        proto_num = int(ip_layer.proto)
        protocol_name = IP_PROTOCOL_MAP.get(proto_num, f"IP-Proto({proto_num})")
    elif packet.haslayer(IPv6):
        ipv6_layer = packet[IPv6]
        src_ip = str(ipv6_layer.src)
        dst_ip = str(ipv6_layer.dst)
        nh_num = int(ipv6_layer.nh)
        protocol_name = IP_PROTOCOL_MAP.get(nh_num, f"IPv6-NextHdr({nh_num})")
    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        src_ip = str(arp_layer.psrc)
        dst_ip = str(arp_layer.pdst)
        protocol_name = "ARP"
        protocol_category = "Other"

    # Layer 4 / Transport Layer resolution
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags_str: Optional[str] = None
    tcp_flags_expanded: Optional[List[str]] = None

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        protocol_category = "TCP"
        protocol_name = "TCP"
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        tcp_flags_str, tcp_flags_expanded = parse_tcp_flags(tcp_layer)
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        protocol_category = "UDP"
        protocol_name = "UDP"
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)
    elif packet.haslayer(ICMP) or protocol_name.startswith("ICMP"):
        protocol_category = "ICMP"
        if not packet.haslayer(ICMP):
            protocol_name = "ICMP"
        else:
            icmp_layer = packet[ICMP]
            protocol_name = f"ICMP (Type {icmp_layer.type}, Code {icmp_layer.code})"

    # Payload extraction
    payload_bytes = b""
    if packet.haslayer(Raw):
        payload_bytes = bytes(packet[Raw].load)
    elif packet.haslayer(TCP) and bytes(packet[TCP].payload):
        payload_bytes = bytes(packet[TCP].payload)
    elif packet.haslayer(UDP) and bytes(packet[UDP].payload):
        payload_bytes = bytes(packet[UDP].payload)

    payload_len = len(payload_bytes)

    return ParsedPacketInfo(
        timestamp=timestamp_str,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol_name=protocol_name,
        protocol_category=protocol_category,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags_str=tcp_flags_str,
        tcp_flags_expanded=tcp_flags_expanded,
        payload_len=payload_len,
        payload_bytes=payload_bytes,
    )


def format_packet_summary(info: ParsedPacketInfo) -> str:
    """Generate a clean, single-line color-coded summary for a packet.

    Format:
      [TIMESTAMP] [PROTOCOL] SRC_IP:PORT -> DST_IP:PORT [FLAGS] (Payload: X bytes)

    Args:
        info: Parsed packet information.

    Returns:
        ANSI-colored single-line summary string.
    """
    color = get_protocol_color(info.protocol_category)
    plain_tag = f"[{info.protocol_category}]"
    proto_tag = f"{color}{plain_tag:<16}{Style.RESET_ALL}"

    if info.src_port is not None and info.dst_port is not None:
        endpoints = f"{info.src_ip}:{info.src_port} -> {info.dst_ip}:{info.dst_port}"
    else:
        endpoints = f"{info.src_ip} -> {info.dst_ip}"

    flags_part = ""
    if info.tcp_flags_str:
        flags_part = f" [{info.tcp_flags_str}]"

    return f"[{info.timestamp}] {proto_tag} {endpoints}{flags_part} (Payload: {info.payload_len} B)"


def format_packet_details(info: ParsedPacketInfo) -> str:
    """Generate an expandable detail block showing all protocol metadata.

    Args:
        info: Parsed packet information.

    Returns:
        Formatted detail block string.
    """
    color = get_protocol_color(info.protocol_category)
    proto_label = f"{color}{info.protocol_name}{Style.RESET_ALL}"

    lines: List[str] = [
        f"  |-- Timestamp     : {info.timestamp}",
        f"  |-- Source IP     : {info.src_ip}",
        f"  |-- Destination IP: {info.dst_ip}",
        f"  |-- Protocol      : {proto_label} (Category: {info.protocol_category})",
    ]

    if info.src_port is not None and info.dst_port is not None:
        lines.append(f"  |-- Source Port   : {info.src_port}")
        lines.append(f"  |-- Destination Pt: {info.dst_port}")

    if info.tcp_flags_str is not None:
        expanded_str = (
            ", ".join(info.tcp_flags_expanded) if info.tcp_flags_expanded else "None"
        )
        lines.append(f"  |-- TCP Flags     : [{info.tcp_flags_str}] ({expanded_str})")

    lines.append(f"  |-- Payload Length: {info.payload_len} bytes")
    lines.append("  \\-- Payload Preview (First 64 bytes hex + ASCII):")
    lines.append(format_hex_ascii_dump(info.payload_bytes, max_bytes=64))

    return "\n".join(lines)
