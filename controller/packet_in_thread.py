import threading
from scapy.all import *
from helper import *


class PacketInThread(threading.Thread):
    def __init__(self, switch, controller, daemon=True):
        super().__init__(daemon=daemon)
        self.switch = switch
        self.controller = controller
        self.running = True

    def run(self):
        print(f"--- {self.switch.name} uzerinden paketler dinleniyor... ---")
        while True:
            packet_in = self.switch.PacketIn()
            metadata = packet_in.metadata
            payload = packet_in.payload
            
            in_port = int.from_bytes(metadata[0].value, byteorder='big')
            pkt = Ether(payload)
            src_mac = pkt.src

            if ARP in pkt:
                arp_pkt = pkt[ARP]
                src_ip = arp_pkt.psrc
                src_mac = arp_pkt.hwsrc

                if src_ip not in self.controller.ip_mac_port_dict:
                    print(f"--- [ARP Uzerinden Ogrenildi] {src_ip} -> Port: {in_port} ---")
                    update_ip_mac_port_dict(self.controller, src_ip, src_mac, in_port)
                    write_ipv4_rule(self.controller, src_ip, in_port, src_mac)

            elif IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                proto = pkt[IP].proto  # Protokol numarası (TCP=6, UDP=17, ICMP=1)

                # Portları varsayılan olarak 0 başlat (ICMP vb. için)
                sport = 0
                dport = 0

                # Eğer TCP veya UDP ise portları gerçek değerleriyle güncelle
                if TCP in pkt:
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                elif UDP in pkt:
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                
                # --- Buradan sonra flow_id hesaplamana geçebilirsin ---
                ips = sorted([src_ip, dst_ip])
                ports = sorted([sport, dport])
                
                flow_id = int.from_bytes(metadata[2].value, byteorder='big')
                
                
                if flow_id not in self.controller.flow_stats_dict:
                    fwd_count = int.from_bytes(metadata[5].value, byteorder='big') # Dikkat
                    bwd_count = int.from_bytes(metadata[6].value, byteorder='big') # Dikkat
                    data = {
                        'flow_id': flow_id,
                        'src_ip': ips[0],
                        'dst_ip': ips[1],
                        'proto': proto,
                    }
                    add_flow_stats_dict(self.controller, data)
                    write_flow_tracker_rule(self.controller, flow_id)
                    
                # Track ediliyorsa 

                if src_ip not in self.controller.ip_mac_port_dict:
                    print(f"--- Yeni Host Ogrenildi: {src_ip} ---")
                    update_ip_mac_port_dict(self.controller, src_ip, src_mac, in_port)
                    write_ipv4_rule(self.controller, src_ip, in_port, src_mac)

                if dst_ip in self.controller.ip_mac_port_dict:
                    dst_port = self.controller.ip_mac_port_dict[dst_ip]["port"]
                    send_packet_out(self.controller, dst_port, pkt)
                else:
                    discover_host(self.controller, dst_ip, in_port, src_mac, src_ip)
    ...