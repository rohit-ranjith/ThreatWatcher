from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
from datetime import datetime

log_file = "packet_log.csv"
packets = []

columns = [
    'timestamp',
    'src_ip',
    'src_port',
    'dst_ip',
    'dst_port',
    'protocol_name',
    'length',
    'tcp_flags'
]

# Clear old log and write headers
pd.DataFrame(columns=columns).to_csv(log_file, index=False)

def process_packet(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        length = len(pkt)

        src_port = dst_port = "-"
        protocol_name = "OTHER"
        tcp_flags = "-"

        if TCP in pkt:
            protocol_name = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            tcp_flags = pkt.sprintf("%TCP.flags%")
        elif UDP in pkt:
            protocol_name = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif ICMP in pkt:
            protocol_name = "ICMP"  # New support
        else:
            protocol_name = str(proto)  # fallback for anything else

        packet_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol_name': protocol_name,
            'length': length,
            'tcp_flags': tcp_flags
        }

        packets.append(packet_data)

        # Write every 10 packets to file
        if len(packets) >= 10:
            df = pd.DataFrame(packets)
            df.to_csv(log_file, mode='a', index=False, header=False)
            packets.clear()

#enp0s3 is my VM network interface name
sniff(prn=process_packet, store=False, iface="enp0s3")
