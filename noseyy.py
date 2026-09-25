# noseyy_sniffer.py
from scapy.all import sniff, Ether, IP, TCP, UDP

CYAN = "\033[36m"
GREEN = "\033[32m"
RESET = "\033[0m"
BOLD = "\033[1m"

HEADER = r"""
    _   __                           
   / | / /_  ___  _  _ _  __
  /  |/ / _ \/ __/ _ \/ / / / / / / 
 / /|  / // (_  )  _/ // / /_/ /  
// |/\_/_/\_/\_, /\_, /   
                      /_//_/    
"""

def display_banner():
    print(CYAN + HEADER + RESET)
    print(f"{BOLD}{GREEN}[+] noseyy Packet Sniffer v1.0.0 initialized...{RESET}")
    print("-" * 50)


def process_packet(packet):
    print("\n" + "="*50)
    print(" [ NEW PACKET CAPTURED ]")
    print("="*50)

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
        print(f"   |-- Protocol:        {ip.proto}")

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

def main():
    print("🚀 Starting Packet Sniffer... Press Ctrl+C to stop.")
    # count=0 means run infinitely. filter="ip" captures only IP packets.
    sniff(filter="ip", prn=process_packet, store=False)

if __name__ == "__main__":
    main()
    display_banner()
    