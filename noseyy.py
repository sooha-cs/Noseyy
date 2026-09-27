"""
noseyy Packet Sniffer & Analyzer
A small-scale network monitoring tool for the subject of Computer Networks (micro-project).

Features:
  - Live packet capture (Ctrl+C to stop)
  - Offline analysis of a Wireshark .pcap / .pcapng file
  - Verbose (per-packet) or Quiet (live counter) display modes
  - Auto-generated session report (console + .txt file) at the end of every run
"""

import os
import sys
from datetime import datetime
from collections import Counter

from scapy.all import sniff, rdpcap, Ether, IP, TCP, UDP

CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
RESET = "\033[0m"
BOLD = "\033[1m"
HEADER = r"""

███╗   ██╗ ██████╗ ███████╗███████╗██╗   ██╗██╗   ██╗       ██╗ 
████╗  ██║██╔═══██╗██╔════╝██╔════╝╚██╗ ██╔╝╚██╗ ██╔╝    ██╗╚██╗
██╔██╗ ██║██║   ██║███████╗█████╗   ╚████╔╝  ╚████╔╝     ╚═╝ ██║
██║╚██╗██║██║   ██║╚════██║██╔══╝    ╚██╔╝    ╚██╔╝      ██╗ ██║
██║ ╚████║╚██████╔╝███████║███████╗   ██║      ██║       ╚═╝██╔╝
╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝   ╚═╝      ╚═╝          ╚═╝ 

"""

PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}


# ---------- Session stats (resetting before every capture/analysis run) ----------
class SessionStats:
    def __init__(self):
        self.total_packets = 0
        self.proto_counter = Counter()
        self.src_ip_counter = Counter()
        self.dst_ip_counter = Counter()
        self.start_time = None
        self.end_time = None

    def reset(self):
        self.__init__()


stats = SessionStats()
VERBOSE = True  # toggled per-run by the user

def display_banner():
    print(CYAN + HEADER + RESET)
    print(f"{BOLD}{GREEN}[+] Noseyy Packet Sniffer & Analyzer v2.0.0{RESET}")
    print(f"{GREEN}    A lightweight network monitoring tool{RESET}")
    print("-" * 50)

def display_menu():
    print(f"{BOLD}Choose an option:{RESET}")
    print("  1. Start Live Capture")
    print("  2. Analyze a PCAP File (Wireshark capture)")
    print("  3. Exit")
    return input(f"{BOLD}> {RESET}").strip()


def choose_display_mode():
    print(f"\n{BOLD}Display mode:{RESET}")
    print("  1. Verbose  (full per-packet breakdown - can get noisy)")
    print("  2. Quiet    (live counter only, full report at the end)")
    choice = input(f"{BOLD}> {RESET}").strip()
    return choice != "2"


# ---------- Core packet handler (used for BOTH live capture and pcap analysis) ----------
def process_packet(packet):
    stats.total_packets += 1

    proto_name = "Other"
    if packet.haslayer(IP):
        ip = packet[IP]
        proto_name = PROTO_MAP.get(ip.proto, f"Proto-{ip.proto}")
        stats.src_ip_counter[ip.src] += 1
        stats.dst_ip_counter[ip.dst] += 1
    stats.proto_counter[proto_name] += 1

    if not VERBOSE:
        # Quiet mode: overwrite a single line instead of flooding the console
        print(
            f"\r{GREEN}[Capturing]{RESET} Packets: {stats.total_packets}  |  "
            f"TCP: {stats.proto_counter['TCP']}  UDP: {stats.proto_counter['UDP']}  "
            f"ICMP: {stats.proto_counter['ICMP']}   ",
            end="", flush=True
        )
        return

    print("\n" + "=" * 50)
    print(f" [ PACKET #{stats.total_packets} ]")
    print("=" * 50)

    # --- LAYER 2: ETHERNET ---
    if packet.haslayer(Ether):
        eth = packet[Ether]
        print(f"🔹 [Layer 2 - Data Link] Ethernet Frame")
        print(f"   |-- Source MAC:      {eth.src}")
        print(f"   |-- Destination MAC: {eth.dst}")
        print(f"   |-- Protocol Type:   {hex(eth.type)}")

    # --- LAYER 3: IP ---
    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"🔸 [Layer 3 - Network] IP Packet")
        print(f"   |-- Source IP:       {ip.src}")
        print(f"   |-- Destination IP:  {ip.dst}")
        print(f"   |-- TTL (Hops):      {ip.ttl}")
        print(f"   |-- Protocol:        {proto_name}")

        # --- LAYER 4: TRANSPORT (TCP) ---
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print(f"🟢 [Layer 4 - Transport] TCP Segment")
            print(f"   |-- Source Port:      {tcp.sport}")
            print(f"   |-- Destination Port: {tcp.dport}")
            print(f"   |-- Sequence Number:  {tcp.seq}")
            print(f"   |-- Flags:            {tcp.flags}")

        # --- LAYER 4: TRANSPORT (UDP) ---
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print(f"🔵 [Layer 4 - Transport] UDP Datagram")
            print(f"   |-- Source Port:      {udp.sport}")
            print(f"   |-- Destination Port: {udp.dport}")
            print(f"   |-- Length:           {udp.len}")


# ---------- Report generation ----------
def generate_report(source_label):
    duration = "N/A"
    if stats.start_time and stats.end_time:
        duration = str(stats.end_time - stats.start_time)

    lines = []
    lines.append("=" * 55)
    lines.append(" NOSEYY PACKET SNIFFER - SESSION REPORT")
    lines.append("=" * 55)
    lines.append(f"Source:            {source_label}")
    lines.append(f"Start Time:        {stats.start_time}")
    lines.append(f"End Time:          {stats.end_time}")
    lines.append(f"Duration:          {duration}")
    lines.append(f"Total Packets:     {stats.total_packets}")
    lines.append("-" * 55)
    lines.append("Protocol Breakdown:")
    if stats.proto_counter:
        for proto, count in stats.proto_counter.most_common():
            lines.append(f"   {proto:<10} : {count}")
    else:
        lines.append("   (no packets captured)")
    lines.append("-" * 55)
    lines.append("Top 5 Source IPs:")
    for ip, count in stats.src_ip_counter.most_common(5):
        lines.append(f"   {ip:<18} : {count} packets")
    lines.append("-" * 55)
    lines.append("Top 5 Destination IPs:")
    for ip, count in stats.dst_ip_counter.most_common(5):
        lines.append(f"   {ip:<18} : {count} packets")
    lines.append("=" * 55)

    report_text = "\n".join(lines)
    print("\n" + CYAN + report_text + RESET)

    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    try:
        with open(filename, "w") as f:
            f.write(report_text)
        print(f"\n{GREEN}[+] Report saved to {filename}{RESET}")
    except OSError as e:
        print(f"\n{RED}[!] Could not save report: {e}{RESET}")


# ---------- Modes ----------
def run_live_capture():
    global VERBOSE
    VERBOSE = choose_display_mode()
    stats.reset()

    count_input = input(f"\n{BOLD}Packet limit (blank = run until Ctrl+C):{RESET} ").strip()
    packet_count = int(count_input) if count_input.isdigit() else 0

    print(f"\n{GREEN}Starting live capture... Press Ctrl+C to stop.{RESET}\n")
    stats.start_time = datetime.now()
    try:
        sniff(filter="ip", prn=process_packet, store=False, count=packet_count)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print(f"{BOLD}{RED}[!] Permission denied. Try running with sudo/administrator privileges.{RESET}")
        return
    finally:
        stats.end_time = datetime.now()
        print(f"\n\n{BOLD}{GREEN}[+] Capture stopped.{RESET}")
        generate_report(source_label="Live Capture")


def run_pcap_analysis():
    global VERBOSE
    path = input(f"\n{BOLD}Path to .pcap / .pcapng file:{RESET} ").strip()
    if not os.path.isfile(path):
        print(f"{RED}[!] File not found: {path}{RESET}")
        return

    VERBOSE = choose_display_mode()
    stats.reset()

    print(f"\n{GREEN}Reading {path} ...{RESET}\n")
    try:
        packets = rdpcap(path)
    except Exception as e:
        print(f"{RED}[!] Failed to read pcap file: {e}{RESET}")
        return

    stats.start_time = datetime.now()
    for pkt in packets:
        process_packet(pkt)
    stats.end_time = datetime.now()

    print(f"\n\n{BOLD}{GREEN}[+] Analysis complete.{RESET}")
    generate_report(source_label=f"PCAP File ({path})")


def main():
    display_banner()
    while True:
        choice = display_menu()
        if choice == "1":
            run_live_capture()
        elif choice == "2":
            run_pcap_analysis()
        elif choice == "3":
            print(f"{GREEN}Goodbye!{RESET}")
            sys.exit(0)
        else:
            print(f"{YELLOW}Invalid option, try again.{RESET}")
        print("\n" + "-" * 50 + "\n")


if __name__ == "__main__":
    main()
