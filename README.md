# PRODIGY_CS_05
Network Packet Analyzer
This is a lightweight Network Packet Analyzer built using Python and the powerful Scapy library. It captures and analyzes live network packets, extracting essential details like source/destination IPs, ports, protocol types, TTL, and even the payload (if available).

Features
1. Real-time packet sniffing using Scapy
2. Identifies and analyzes:
 a. IP layer
 b. TCP & UDP protocols
 c. Packet size and TTL
 d. Payload contents (decoded if possible)
3. Counts and logs each packet inspected
4. Clean and structured terminal output
🖼 Example Output
Packet 1:
Source IP: 192.168.1.10
Destination IP: 93.184.216.34
Source Port: 55672
Destination Port: 80
Packet Size: 60
Packet Type: TCP
TTL: 64
IP Protocol: 6
Payload:
GET /index.html HTTP/1.1
Host: example.com
--------------------------------------------------

This tool is intended for educational and research purposes only. Please ensure you have authorization to sniff traffic on any network you're analyzing. Unauthorized network monitoring may be illegal in your jurisdiction.

🛠 Requirements
Python 3.6+
Scapy

📄 License
This project is licensed under the MIT License.

