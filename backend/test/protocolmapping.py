from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

# A list to store the captured packets
captured_packets = []

# Protocol mapping dictionary
protocol_map = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    # Add more protocol numbers as needed
}

def packet_callback(packet):
    global captured_packets
    if IP in packet:
        protocol_number = packet[IP].proto
        protocol_name = protocol_map.get(protocol_number, 'Unknown')
        
        packet_info = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': protocol_name,
            'length': len(packet)
        }
        captured_packets.append(packet_info)
        
        # Limit to the top 10 recent packets
        if len(captured_packets) > 10:
            captured_packets.pop(0)
        
        # Print the top 10 recent packets
        print("\nTop 10 Recent Packets:")
        for i, pkt in enumerate(captured_packets, start=1):
            print(f"{i}: Timestamp: {pkt['timestamp']}, Source IP: {pkt['src_ip']}, Destination IP: {pkt['dst_ip']}, Protocol: {pkt['protocol']}, Length: {pkt['length']}")

def main():
    # Capture packets indefinitely
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
