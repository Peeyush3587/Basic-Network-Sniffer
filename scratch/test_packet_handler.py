"""Verification script for packet_handler module.

Uses plain assert statements to test parsing and formatting functions
against synthetic Scapy packets without requiring live network capture
or root/admin privileges.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from colorama import Fore
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from network_sniffer.packet_handler import (
    PacketStats,
    format_hex_ascii_dump,
    format_packet_details,
    format_packet_summary,
    get_protocol_color,
    parse_packet,
    parse_tcp_flags,
)
from network_sniffer.sniffer import SnifferEngine


def test_color_mapping() -> None:
    """Verify protocol color mappings."""
    print("[*] Testing protocol color mapping...")
    assert get_protocol_color("TCP") == Fore.BLUE, "TCP should be blue"
    assert get_protocol_color("UDP") == Fore.GREEN, "UDP should be green"
    assert get_protocol_color("ICMP") == Fore.YELLOW, "ICMP should be yellow"
    assert get_protocol_color("Other") == Fore.WHITE, "Other should be white"
    assert get_protocol_color("ARP") == Fore.WHITE, "ARP should map to white"
    print("    [+] Color mapping passed.")


def test_hex_ascii_dump() -> None:
    """Verify hex and ASCII dump formatting."""
    print("[*] Testing hex/ASCII dump...")
    empty_dump = format_hex_ascii_dump(b"")
    assert "No payload data" in empty_dump

    sample = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    dump = format_hex_ascii_dump(sample, max_bytes=64)
    assert "0000" in dump
    assert "GET /in" in dump
    assert "example.com" in dump
    # Non-printable characters \r\n should be replaced with '.'
    assert ".." in dump
    print("    [+] Hex/ASCII dump formatting passed.")


def test_tcp_packet_parsing() -> None:
    """Verify parsing of a synthetic TCP packet."""
    print("[*] Testing TCP packet parsing...")
    pkt = (
        Ether()
        / IP(src="192.168.1.50", dst="93.184.216.34")
        / TCP(sport=54321, dport=80, flags="S")
        / Raw(load=b"SYN_TEST_DATA_12345")
    )

    info = parse_packet(pkt)
    assert info.src_ip == "192.168.1.50"
    assert info.dst_ip == "93.184.216.34"
    assert info.protocol_category == "TCP"
    assert info.protocol_name == "TCP"
    assert info.src_port == 54321
    assert info.dst_port == 80
    assert "S" in (info.tcp_flags_str or "")
    assert any("SYN" in flag for flag in (info.tcp_flags_expanded or []))
    assert info.payload_len == len(b"SYN_TEST_DATA_12345")
    assert info.payload_bytes == b"SYN_TEST_DATA_12345"

    summary = format_packet_summary(info)
    assert "192.168.1.50:54321 -> 93.184.216.34:80" in summary
    assert "[S]" in summary

    details = format_packet_details(info)
    assert "Source Port   : 54321" in details
    assert "Destination Pt: 80" in details
    assert "SYN" in details
    assert "SYN_TEST_DATA" in details
    print("    [+] TCP packet parsing passed.")


def test_udp_packet_parsing() -> None:
    """Verify parsing of a synthetic UDP packet."""
    print("[*] Testing UDP packet parsing...")
    pkt = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=53, dport=45678)
        / Raw(load=b"DNS_QUERY_PAYLOAD")
    )

    info = parse_packet(pkt)
    assert info.src_ip == "10.0.0.1"
    assert info.dst_ip == "10.0.0.2"
    assert info.protocol_category == "UDP"
    assert info.src_port == 53
    assert info.dst_port == 45678
    assert info.payload_len == len(b"DNS_QUERY_PAYLOAD")

    summary = format_packet_summary(info)
    assert "10.0.0.1:53 -> 10.0.0.2:45678" in summary

    details = format_packet_details(info)
    assert "Source Port   : 53" in details
    assert "Destination Pt: 45678" in details
    print("    [+] UDP packet parsing passed.")


def test_icmp_packet_parsing() -> None:
    """Verify parsing of a synthetic ICMP packet."""
    print("[*] Testing ICMP packet parsing...")
    pkt = (
        Ether()
        / IP(src="192.168.1.1", dst="8.8.8.8")
        / ICMP(type=8, code=0)
        / Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi")
    )

    info = parse_packet(pkt)
    assert info.src_ip == "192.168.1.1"
    assert info.dst_ip == "8.8.8.8"
    assert info.protocol_category == "ICMP"
    assert "Type 8" in info.protocol_name
    assert info.src_port is None
    assert info.dst_port is None

    summary = format_packet_summary(info)
    assert "192.168.1.1 -> 8.8.8.8" in summary

    details = format_packet_details(info)
    assert "ICMP" in details
    assert "Type 8" in details
    print("    [+] ICMP packet parsing passed.")


def test_packet_stats() -> None:
    """Verify PacketStats counter logic."""
    print("[*] Testing PacketStats counters...")
    stats = PacketStats()
    assert stats.total_packets == 0
    assert stats.parse_errors == 0
    assert stats.protocol_counts["TCP"] == 0

    stats.record_packet("TCP")
    stats.record_packet("TCP")
    stats.record_packet("UDP")
    stats.record_packet("ICMP")
    stats.record_packet("UnknownProtocol")

    assert stats.total_packets == 5
    assert stats.protocol_counts["TCP"] == 2
    assert stats.protocol_counts["UDP"] == 1
    assert stats.protocol_counts["ICMP"] == 1
    assert stats.protocol_counts["Other"] == 1
    print("    [+] PacketStats counter passed.")


def test_process_packet_survives_malformed_packet() -> None:
    """Verify that a malformed packet does not crash process_packet and increments parse_errors."""
    print("[*] Testing process_packet error boundary on malformed packet...")
    engine = SnifferEngine()
    assert engine.stats.parse_errors == 0
    assert engine.stats.total_packets == 0

    # Pass an invalid non-Packet object to trigger an exception inside process_packet's try block
    engine.process_packet("not_a_valid_scapy_packet")  # type: ignore[arg-type]

    # Assert exception did not escape, parse_errors incremented, and total_packets remained unchanged
    assert engine.stats.parse_errors == 1, "parse_errors should have incremented to 1"
    assert engine.stats.total_packets == 0, "total_packets should not increment on parse failure"
    print("    [+] Malformed packet handling passed.")


def main() -> None:
    """Run all verification checks."""
    print("=== Running Packet Handler Verification Tests ===")
    test_color_mapping()
    test_hex_ascii_dump()
    test_tcp_packet_parsing()
    test_udp_packet_parsing()
    test_icmp_packet_parsing()
    test_packet_stats()
    test_process_packet_survives_malformed_packet()
    print("=== ALL VERIFICATION TESTS PASSED SUCCESSFULLY! ===")


if __name__ == "__main__":
    main()
