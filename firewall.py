from scapy.all import sniff, IP, TCP, UDP
import logging

# Configure logging to save blocked packets
logging.basicConfig(filename="firewall_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# Blocked IPs and Ports (can be updated via GUI)
BLOCKED_IPS = ["192.168.1.10", "10.0.0.5"]
BLOCKED_PORTS = [80, 443, 22, 3389]  # Blocks HTTP, HTTPS, SSH, RDP

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if src_ip in BLOCKED_IPS or dst_ip in BLOCKED_IPS:
            print(f"🚨 Blocked packet from {src_ip} to {dst_ip}")
            logging.info(f"Blocked IP packet: {src_ip} -> {dst_ip}")
            return

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            src_port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
            dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport

            if src_port in BLOCKED_PORTS or dst_port in BLOCKED_PORTS:
                print(f"🚨 Blocked TCP/UDP packet on port {dst_port} from {src_ip}")
                logging.info(f"Blocked port packet: {src_ip} -> {dst_port}")
                return

        print(f"✅ Allowed packet from {src_ip} to {dst_ip}")

# Start packet sniffing
print("🚀 Firewall is running... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)
