# port_scan.py
from scapy.all import *
import time

target_ip = "10.0.5.11"
# Bu sefer tek bir kaynak IP kullanıyoruz (h10'un kendi IP'si gibi davranabilir)
print(f"Port tarama baslatiliyor: {target_ip}")

for port in range(1, 201): # İlk 200 portu tara
    pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
    send(pkt, verbose=0)
    # Biraz bekleme ekleyebiliriz ki gerçekçi olsun
    time.sleep(0.01)

print("Tarama bitti.")