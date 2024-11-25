from scapy.all import *
import socket
import datetime
import csv

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        print(f"Error retrieving local IP: {e}")
        return "127.0.0.1" 

local_ip = get_local_ip()

captured_packets = []

def packet_to_dict(pkt):
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
    try:
        packet_data = packet_to_dict(pkt)
        if packet_data:  
            captured_packets.append(packet_data)
            print(packet_data)
    except Exception as e:
        print(f"Error processing packet: {e}")

def save_to_csv(filename, data):
    # save captured packets to csv file
    try:
        if not data:
            print("No packets captured to save.")
            return
        with open(filename, "w", newline="") as csvfile:
            fieldnames = [
                "timestamp", "protocol", "direction", "src_mac", "dst_mac",
                "src_ip", "dst_ip", "src_port", "dst_port", "length"
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        print(f"Captured packets saved to {filename}")
    except Exception as e:
        print(f"Error saving to CSV: {e}")

def main():
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

main()