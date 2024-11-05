# Implement your ICMP receiver here
from scapy.all import sniff, ICMP, IP

def handle_packet(packet):
    if packet.haslayer(ICMP) and packet[IP].ttl == 1:
        packet.show()

sniff(filter="icmp", prn=handle_packet,count=1)
