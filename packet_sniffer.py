from scapy.all import *
import socket
import datetime
import csv

def get_local_ip():
    try:
        # Get the local network IP address of the host
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        print(f"Error retrieving local IP: {e}")
        return "127.0.0.1"  # Fallback to localhost

# Local IP address of the machine
local_ip = get_local_ip()

# List to store captured packets
captured_packets = []

def packet_to_dict(pkt):
    """Convert a packet to a dictionary format for logging or saving."""
    try:
        # Get MAC addresses
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "Unknown"
        dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else "Unknown"

        # Handle TCP Packets
        if pkt.haslayer(TCP):
            ip_layer = IP if pkt.haslayer(IP) else IPv6
            direction = "IN" if pkt[ip_layer].dst == local_ip else "OUT"
            return {
                "timestamp": datetime.datetime.now().isoformat(),
                "protocol": "TCP",
                "direction": direction,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "src_ip": pkt[ip_layer].src,
                "dst_ip": pkt[ip_layer].dst,
                "src_port": pkt[TCP].sport,
                "dst_port": pkt[TCP].dport,
                "length": len(pkt),
            }
        # Handle UDP Packets
        elif pkt.haslayer(UDP):
            ip_layer = IP if pkt.haslayer(IP) else IPv6
            direction = "IN" if pkt[ip_layer].dst == local_ip else "OUT"
            return {
                "timestamp": datetime.datetime.now().isoformat(),
                "protocol": "UDP",
                "direction": direction,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "src_ip": pkt[ip_layer].src,
                "dst_ip": pkt[ip_layer].dst,
                "src_port": pkt[UDP].sport,
                "dst_port": pkt[UDP].dport,
                "length": len(pkt),
            }
        # Handle ICMP Packets
        elif pkt.haslayer(ICMP):
            ip_layer = IP if pkt.haslayer(IP) else IPv6
            direction = "IN" if pkt[ip_layer].dst == local_ip else "OUT"
            return {
                "timestamp": datetime.datetime.now().isoformat(),
                "protocol": "ICMP",
                "direction": direction,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "src_ip": pkt[ip_layer].src,
                "dst_ip": pkt[ip_layer].dst,
                "icmp_type": pkt[ICMP].type,
                "icmp_code": pkt[ICMP].code,
                "length": len(pkt),
            }
        # Handle DNS Packets
        elif pkt.haslayer(DNS):
            ip_layer = IP if pkt.haslayer(IP) else IPv6
            direction = "IN" if pkt[ip_layer].dst == local_ip else "OUT"
            return {
                "timestamp": datetime.datetime.now().isoformat(),
                "protocol": "DNS",
                "direction": direction,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "src_ip": pkt[ip_layer].src,
                "dst_ip": pkt[ip_layer].dst,
                "dns_query": pkt[DNS].qd.qname.decode() if pkt[DNS].qd else "N/A",
                "dns_response": pkt[DNS].an.rdata if pkt[DNS].an else "N/A",
                "length": len(pkt),
            }
        # Handle ARP Packets
        elif pkt.haslayer(ARP):
            direction = "IN" if pkt[ARP].pdst == local_ip else "OUT"
            return {
                "timestamp": datetime.datetime.now().isoformat(),
                "protocol": "ARP",
                "direction": direction,
                "src_mac": pkt[ARP].hwsrc,
                "dst_mac": pkt[ARP].hwdst,
                "src_ip": pkt[ARP].psrc,
                "dst_ip": pkt[ARP].pdst,
                "length": len(pkt),
            }
        else:
            return {
                "timestamp": datetime.datetime.now().isoformat(),
                "protocol": "Unknown",
                "direction": "Unknown",
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "src_ip": "N/A",
                "dst_ip": "N/A",
                "length": len(pkt),
            }
    except Exception as e:
        print(f"Error converting packet to dictionary: {e}")
        return None

def network_monitoring(pkt):
    """Callback function to process each captured packet."""
    try:
        packet_data = packet_to_dict(pkt)
        if packet_data:  # Ensure valid data is appended
            captured_packets.append(packet_data)
            print(packet_data)
    except Exception as e:
        print(f"Error processing packet: {e}")

def save_to_csv(filename, data):
    """Save captured packet data to a CSV file."""
    try:
        if not data:  # Check if there are any packets to save
            print("No packets captured to save.")
            return
        with open(filename, "w", newline="") as csvfile:
            fieldnames = [
                "timestamp", "protocol", "direction", "src_mac", "dst_mac",
                "src_ip", "dst_ip", "src_port", "dst_port", "icmp_type",
                "icmp_code", "dns_query", "dns_response", "length"
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        print(f"Captured packets saved to {filename}")
    except Exception as e:
        print(f"Error saving to CSV: {e}")

if __name__ == '__main__':
    try:
        capture_duration = int(input("Enter the duration (in seconds) for live packet capture: ").strip())
        print(f"Starting network monitoring for {capture_duration} seconds on local IP: {local_ip}...")
        sniff(prn=network_monitoring, timeout=capture_duration)
        print("\n\nCapture duration ended. Saving results...")
        csv_filename = "packet_sniffer_results.csv"
        save_to_csv(csv_filename, captured_packets)
    except ValueError:
        print("Invalid input. Please enter a valid integer for the duration.")
    except Exception as e:
        print(f"Unexpected error: {e}")
