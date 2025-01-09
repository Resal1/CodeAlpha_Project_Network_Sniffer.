# CodeAlpha_Project_Network_Sniffer.
A Python-based tool to capture, decode, and analyze network traffic in real-time. This sniffer leverages raw sockets to provide insights into how data flows through a network, making it an excellent learning tool and a utility for network troubleshooting
🔑 Features

    Ethernet Frame Decoding: Extract source/destination MAC addresses and protocol type.
    IPv4 Packet Analysis: Detailed unpacking of IPv4 headers, including version, TTL, source, and destination IPs.
    Protocol Support:
        ICMP: Extract type, code, and checksum.
        TCP: Decode source/destination ports, sequence numbers, acknowledgment numbers, and flags.
        UDP: Extract source/destination ports and data length.
    Readable Output: Display packet data payload in a clean and formatted way.

📚 Use Cases

    Network Security: Detect anomalies and inspect suspicious traffic.
    Education: Learn about network protocols and packet structures.
    Debugging: Analyze data flow and troubleshoot connectivity issues.

🚀 Getting Started

    Clone the repository: 

git clone https://github.com/Resal1/CodeAlpha_Project_Network_SnifferX.git   

Run the script with root/admin privileges:
    chmod +x Network_SnifferX.py

    sudo python3 Network_SnifferX.py  

    Observe real-time network traffic!

🛠️ Future Improvements

    Add support for IPv6 packets.
    Extend protocol support (DNS, HTTP, etc.).
    Integrate graphical tools for better traffic visualization.

🤝 Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.
📄 License

This project is licensed under the MIT License.
