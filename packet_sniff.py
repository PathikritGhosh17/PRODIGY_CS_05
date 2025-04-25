#Network Packet Analyzer
from scapy.all import sniff, IP, TCP, UDP, Raw

# Variable to store the number of packets
packet_count = 0

# Define the IDS function
def packet_callback(packet):
    global packet_count
    packet_count += 1

    # Check if the packet has an IP layer
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_size = len(packet)
        ttl = packet[IP].ttl
        ip_protocol = packet[IP].proto

        # Check if the packet has TCP or UDP layer
        if TCP in packet:
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            packet_type = "TCP"
        elif UDP in packet:
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
            packet_type = "UDP"
        else:
            source_port = None
            destination_port = None
            packet_type = "Other"

        # Print the packet details
        print(f"Packet {packet_count}:")
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Source Port: {source_port}")
        print(f"Destination Port: {destination_port}")
        print(f"Packet Size: {packet_size}")
        print(f"Packet Type: {packet_type}")
        print(f"TTL: {ttl}")
        print(f"IP Protocol: {ip_protocol}")

        # Display payload if available
        if Raw in packet:
            try:
                payload = packet[Raw].load.decode('utf-8', errors='replace')
                print(f"Payload:\n{payload}")
            except Exception as e:
                print(f"Payload (raw bytes): {packet[Raw].load}")
        else:
            print("Payload: None")

        print("-" * 50)

# Sniff packets and analyze them
print("Starting IDS...")
sniff(prn=packet_callback, store=0, count=500)
print(f"Total number of packets analyzed: {packet_count}")
