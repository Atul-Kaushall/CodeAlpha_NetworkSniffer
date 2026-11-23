```python
from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto

        # Determine protocol name
        if proto_num == 6 and TCP in packet:
            protocol = "TCP"
            ports = f"{packet[TCP].sport} -> {packet[TCP].dport}"
        elif proto_num == 17 and UDP in packet:
            protocol = "UDP"
            ports = f"{packet[UDP].sport} -> {packet[UDP].dport}"
        elif proto_num == 1 and ICMP in packet:
            protocol = "ICMP"
            ports = "N/A"
        else:
            protocol = f"Other ({proto_num})"
            ports = "N/A"

        print(f"[{protocol}] {src_ip} -> {dst_ip} | Ports: {ports}")

        # Display raw payload snippet if present
        if packet.haslayer("Raw"):
            payload = bytes(packet["Raw"].load)
            print(f"   Payload (first 50 bytes): {payload[:50]}")

def start_sniffer(packet_count=20):
    print(f"Starting network sniffer (capturing {packet_count} packets)...")
    print("Press Ctrl+C to stop early.\n")
    # Note: Requires Administrator/Root privileges to capture packets
    sniff(prn=packet_callback, count=packet_count, store=False)
    print("\nCapture complete.")

if __name__ == "__main__":
    start_sniffer(packet_count=20)
