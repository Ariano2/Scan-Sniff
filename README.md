Sniff+Scan: A Simple Network Scanner

# Introduction
  Sniff+Scan is a lightweight and easy-to-use tool that performs two essential network-related tasks:
  
  Port Scanning: Scans all ports (0–65535) on your localhost to identify which ones are open.
  Wi-Fi Packet Sniffing: Captures Wi-Fi packets and logs the data for analysis.
  The project is designed to run efficiently using multithreading, which speeds up port scanning by scanning multiple ports at the same time.

# Features
  Fast Port Scanning: Quickly detects open ports on your localhost.
  Packet Logging: Captures and logs network packet transfers over Wi-Fi.
  Data Storage:
  Open ports are saved to a text file (open_ports.txt).
  Packet data is logged to a CSV file (packet_data.csv).

# Requirements
  To run Sniff+Scan, you need:
  
  Python 3.x installed on your system.
  Admin or root permissions (required for packet sniffing).
  Required Python libraries:
  scapy (for packet sniffing)
  socket (for port scanning)
  csv and threading (built into Python)
  You can install scapy by running:
  pip install scapy

# How to Use

  Clone the Project: Download or clone the Sniff+Scan repository:
  
  git clone https://github.com/your-username/sniff-scan.git
  
  cd sniff-scan
  
  Run the Program: Execute the script:
  
  python main.py
  Note: Use sudo or run as an administrator if you're sniffing packets.
  
  Check the Results:
  
  Open ports will be listed in port_scanner_results.txt
  Packet logs will be stored in packet_sniffer_results.csv

# Output Files (Sample)
  port_scanner_results.txt : Lists all open ports on your localhost, like this:
  
  Open Ports:
  22
  80
  443
  
  packet_sniffer_results.csv : Logs packet information in a table-like format:
  
  
  Timestamp, Source IP, Destination IP, Protocol, Length
  2024-11-24 12:34:56, 192.168.0.1, 192.168.0.2, TCP, 128
  
  Note actual output of files may vary

# Limitations

  This tool only scans the localhost (your own computer).
  Packet sniffing requires admin/root access.
  The tool is for educational purposes only. Please do not use it on networks without permission.
