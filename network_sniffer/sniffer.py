"""Basic Network Sniffer CLI Entry Point.

A clean, cross-platform CLI tool for learning network and protocol fundamentals.
Captures and dissects network traffic using Scapy, with color-coded terminal output.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

from colorama import Fore, Style, init as colorama_init
from scapy.all import conf, get_if_list, sniff
from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.utils import PcapWriter

from network_sniffer.packet_handler import (
    PacketStats,
    format_packet_details,
    format_packet_summary,
    parse_packet,
)

colorama_init(autoreset=True)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def print_ethical_banner() -> None:
    """Display an ethical usage warning banner."""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}======================================================================
[*] BASIC NETWORK SNIFFER - Educational Protocol Analyzer
[*]
[*] WARNING: This tool is intended solely for educational purposes
[*] and authorized network analysis. Unauthorized packet capture on
[*] networks you do not own or have explicit authorization to monitor
[*] may be illegal under local, federal, and international law.
======================================================================{Style.RESET_ALL}
"""
    print(banner.strip())
    print()


def list_network_interfaces() -> None:
    """Print available network interfaces and exit."""
    print(f"{Fore.GREEN}[*] Discovering network interfaces...{Style.RESET_ALL}\n")
    try:
        # conf.ifaces provides human-readable interface mappings across platforms
        if hasattr(conf, "ifaces") and conf.ifaces:
            print(str(conf.ifaces))
        else:
            if_list = get_if_list()
            print("Available Interface Names:")
            for idx, iface_name in enumerate(if_list, start=1):
                print(f"  [{idx}] {iface_name}")
    except Exception as exc:  # pylint: disable=broad-except
        print(f"{Fore.YELLOW}[!] Could not retrieve detailed interface list: {exc}{Style.RESET_ALL}")
        if_list = get_if_list()
        print("Fallback Interface List:")
        for iface_name in if_list:
            print(f"  - {iface_name}")


def print_capture_summary(stats: PacketStats) -> None:
    """Print a summary table of captured packets broken down by protocol.

    Args:
        stats: PacketStats counter instance.
    """
    total = stats.total_packets
    print("\n" + "=" * 54)
    print(f"{Fore.CYAN}{Style.BRIGHT}                 CAPTURE SUMMARY{Style.RESET_ALL}")
    print("=" * 54)
    print(f"Total Packets Captured: {Style.BRIGHT}{total}{Style.RESET_ALL}\n")
    print("Protocol Breakdown:")

    categories = [
        ("TCP", Fore.BLUE),
        ("UDP", Fore.GREEN),
        ("ICMP", Fore.YELLOW),
        ("Other", Fore.WHITE),
    ]

    for cat_name, color in categories:
        count = stats.protocol_counts.get(cat_name, 0)
        percentage = (count / total * 100) if total > 0 else 0.0
        print(
            f"  - {color}{cat_name:<6}{Style.RESET_ALL}: "
            f"{count:>5} packets ({percentage:>5.1f}%)"
        )
    if stats.parse_errors > 0:
        print(f"\n  {Fore.RED}[!] Parse Errors Encountered: {stats.parse_errors} packets{Style.RESET_ALL}")
    print("=" * 54)


def handle_permission_error() -> None:
    """Print an OS-specific message when packet capture fails due to lack of privileges."""
    print(f"\n{Fore.RED}[!] Permission Error: Insufficient privileges to capture raw packets.{Style.RESET_ALL}")
    if sys.platform.startswith("win"):
        print(
            f"{Fore.YELLOW}Windows troubleshooting:\n"
            f"  1. Run this terminal as Administrator.\n"
            f"  2. Make sure Npcap is installed (https://npcap.com) with "
            f"'WinPcap API-compatible mode' checked.{Style.RESET_ALL}"
        )
    else:
        print(
            f"{Fore.YELLOW}Linux troubleshooting:\n"
            f"  - Try running with sudo, or set capabilities:\n"
            f"    sudo setcap cap_net_raw+eip $(which python3){Style.RESET_ALL}"
        )


class SnifferEngine:
    """Encapsulates the sniffing session state and packet processing."""

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        packet_count: int = 0,
        save_path: Optional[str] = None,
    ) -> None:
        """Initialize the SnifferEngine.

        Args:
            interface: Network interface to capture on (None for default).
            bpf_filter: Berkeley Packet Filter string (e.g. "tcp port 80").
            packet_count: Number of packets to capture (0 = infinite).
            save_path: Optional file path to save captured packets in .pcap format.
        """
        self.interface = interface
        self.bpf_filter = bpf_filter or ""
        self.packet_count = packet_count
        self.save_path = save_path
        self.stats = PacketStats()
        self.pcap_writer: Optional[PcapWriter] = None
        self.capture_failed: bool = False

    def process_packet(self, packet: Packet) -> None:
        """Callback invoked by Scapy for each captured packet.

        Args:
            packet: Captured Scapy packet.
        """
        try:
            info = parse_packet(packet)
            self.stats.record_packet(info.protocol_category)

            # Print single-line summary
            print(format_packet_summary(info))

            # Print expandable detail block
            print(format_packet_details(info))
            print(f"{Fore.BLACK}{Style.BRIGHT}{'-' * 70}{Style.RESET_ALL}")

            # Stream packet to PCAP file if enabled
            if self.pcap_writer is not None:
                try:
                    self.pcap_writer.write(packet)
                except Exception as write_err:  # pylint: disable=broad-except
                    print(f"{Fore.RED}[!] Failed to write packet to PCAP: {write_err}{Style.RESET_ALL}", file=sys.stderr)
        except Exception as err:  # pylint: disable=broad-except
            self.stats.parse_errors += 1
            print(f"{Fore.RED}[!] Failed to parse packet: {err}{Style.RESET_ALL}", file=sys.stderr)

    def run(self) -> None:
        """Execute the packet sniffing loop with error handling."""
        try:
            try:
                if self.save_path:
                    # Ensure target directory exists
                    dirname = os.path.dirname(self.save_path)
                    if dirname:
                        os.makedirs(dirname, exist_ok=True)
                    self.pcap_writer = PcapWriter(self.save_path, append=True, sync=True)
                    print(f"{Fore.CYAN}[*] Writing captured packets to: {self.save_path}{Style.RESET_ALL}")

                print(f"{Fore.GREEN}[*] Starting packet capture...{Style.RESET_ALL}")
                if self.interface:
                    print(f"    Interface : {self.interface}")
                else:
                    print("    Interface : Scapy Default Interface")

                if self.bpf_filter:
                    print(f"    BPF Filter: {self.bpf_filter}")
                else:
                    print("    BPF Filter: None (capturing all IP traffic)")

                if self.packet_count > 0:
                    print(f"    Count     : {self.packet_count} packets")
                else:
                    print("    Count     : Continuous (Press Ctrl+C to stop)")

                print(f"{Fore.BLACK}{Style.BRIGHT}{'=' * 70}{Style.RESET_ALL}")

                sniff(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=self.process_packet,
                    count=self.packet_count,
                    store=False,  # Keep memory footprint constant and lightweight
                )
            except (PermissionError, Scapy_Exception, OSError, ValueError) as exc:
                self.capture_failed = True
                err_msg = str(exc).lower()
                if isinstance(exc, ValueError) or "interface" in err_msg:
                    print(
                        f"\n{Fore.RED}[!] Interface not found. Run --list-interfaces to see available options.{Style.RESET_ALL}",
                        file=sys.stderr,
                    )
                elif "pcap" in err_msg or "file" in err_msg or (self.save_path and self.pcap_writer is None):
                    print(
                        f"\n{Fore.RED}[!] Failed to create output PCAP file: {self.save_path}{Style.RESET_ALL}",
                        file=sys.stderr,
                    )
                elif (
                    "permission" in err_msg
                    or "operation not permitted" in err_msg
                    or "access is denied" in err_msg
                    or "wpcap" in err_msg
                    or "pcap" in err_msg
                ):
                    handle_permission_error()
                else:
                    print(f"\n{Fore.RED}[!] Capture error: {exc}{Style.RESET_ALL}", file=sys.stderr)
        finally:
            if self.pcap_writer is not None:
                self.pcap_writer.close()
                print(f"{Fore.CYAN}[*] PCAP file saved successfully: {self.save_path}{Style.RESET_ALL}")
            print_capture_summary(self.stats)


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser.

    Returns:
        Configured argparse.ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="network_sniffer",
        description="A clean, cross-platform CLI Network Sniffer for learning network protocols.",
        epilog="Example: python -m network_sniffer.sniffer -i 'eth0' -f 'tcp port 80' -c 10 -o capture.pcap",
    )

    parser.add_argument(
        "--iface", "-i",
        type=str, default=None,
        help="Network interface to sniff on (optional, default = Scapy's default)",
    )
    parser.add_argument(
        "--filter", "-f",
        type=str, default=None,
        help="BPF filter string, e.g. 'tcp port 80' or 'udp' (optional)",
    )
    parser.add_argument(
        "--count", "-c",
        type=int, default=0,
        help="Number of packets to capture, 0 = infinite (default: 0)",
    )
    parser.add_argument(
        "--save", "-o",
        type=str, default=None,
        help="Optional PCAP file path to save captured packets",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit",
    )

    return parser


def main() -> None:
    """Entrypoint function for the CLI application."""
    parser = build_parser()
    args = parser.parse_args()

    # Handle --list-interfaces flag
    if args.list_interfaces:
        list_network_interfaces()
        sys.exit(0)

    # Print educational ethical banner
    print_ethical_banner()

    # Validate count argument
    if args.count < 0:
        print(f"{Fore.RED}[!] Error: --count cannot be negative.{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)

    engine = SnifferEngine(
        interface=args.iface,
        bpf_filter=args.filter,
        packet_count=args.count,
        save_path=args.save,
    )
    try:
        engine.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Capture interrupted by user (Ctrl+C).{Style.RESET_ALL}")

    if engine.capture_failed:
        sys.exit(1)


if __name__ == "__main__":
    main()