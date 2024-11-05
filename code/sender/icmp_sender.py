# Implement your ICMP sender here
from scapy.all import ICMP, IP, send

packet = IP(dst="172.18.0.2", ttl=1) / ICMP()
send(packet)

