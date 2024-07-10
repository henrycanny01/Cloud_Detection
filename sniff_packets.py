import argparse
from scapy.all import sniff
import pandas as pd
from datetime import datetime

# Function to process each packet
def process_packet(packet):
    packet_info = {
        'timestamp': datetime.now(),
        'src_mac': packet.src if packet.haslayer('Ether') else None,
        'dst_mac': packet.dst if packet.haslayer('Ether') else None,
        'src_ip': packet[1].src if packet.haslayer('IP') else None,
        'dst_ip': packet[1].dst if packet.haslayer('IP') else None,
        'src_port': packet.sport if packet.haslayer('TCP') or packet.haslayer('UDP') else None,
        'dst_port': packet.dport if packet.haslayer('TCP') or packet.haslayer('UDP') else None,
        'proto': packet.proto if packet.haslayer('IP') else None,
        'length': len(packet)
    }
    packets_list.append(packet_info)

# List to store packet details
packets_list = []

# Argument parser setup
parser = argparse.ArgumentParser(description='Sniff network packets and save them to a CSV file.')
parser.add_argument('--iface', type=str, required=True, help='Network interface to sniff on (e.g., "WiFi", "eth0").')
parser.add_argument('--count', type=int, required=True, help='Number of packets to capture.')

args = parser.parse_args()

# Sniff packets
sniff(iface=args.iface, prn=process_packet, count=args.count)

# Create a DataFrame from the packets list
packets_df = pd.DataFrame(packets_list)

# Save the DataFrame to a CSV file
packets_df.to_csv('packets.csv', index=False)

print("Packet capture complete. Data saved to packets.csv")
