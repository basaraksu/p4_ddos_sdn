import sys
import os
from scapy.all import Ether, IP, ARP

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../../utils/'))

import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4.v1 import p4runtime_pb2


db_ip_mac_port = {}  # IP-MAC-Port bilgilerini tutacak sözlük
active_ports = [1, 2, 3]  # Aktif portları tutan liste (örneğin 1, 2, 3 numaralı portlar)

def main():
    p4info_file = "../build/ddos_detection.p4.p4info.txtpb"
    bmv2_json = "../build/ddos_detection.json"
    
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file)

    # Switch Bağlantısını Kur
    s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='s1',
        address='127.0.0.1:50051',
        device_id=0)

    s1.MasterArbitrationUpdate()
    
    s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                        bmv2_json_file_path=bmv2_json)
    print("P4 program yüklendi ve switch hazır!")
    #print(dir(p4info_helper))
    receive_packet_in(s1, p4info_helper) 
...


def discover_host(switch, p4info_helper, target_ip, ingress_port, sender_mac, sender_ip):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=sender_mac) / \
          ARP(op=1, hwsrc=sender_mac, psrc=sender_ip, pdst=target_ip)
    
    # Tüm portlara (flood) veya bilinen portlara Packet-Out fırlat
    for port in active_ports:
        if port != ingress_port:  # Paketi geldiği port hariç her yere gönder
            send_packet_out(switch, port, pkt)
...


from p4.v1 import p4runtime_pb2

def send_packet_out(switch, egress_port, pkt):
    payload = bytes(pkt)
    metadatas = [
        {
            "value": egress_port, 
            "bitwidth": 16
        }
    ]

    try:
        switch.PacketOut(payload, metadatas)
        print(f"--- [Packet-Out] Port {egress_port} BAŞARILI! ---")
    except Exception as e:
        print(f"!!! Packet-Out hala başarısız: {e}")
...


# Switch'e yeni bir kural yazmak için kullanılan fonksiyon
def write_ipv4_rule(switch, p4info_helper, ip_addr, port, mac_addr):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (ip_addr, 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "port": port,
            "dstAddr": mac_addr
        })
    switch.WriteTableEntry(table_entry)
...




def update_db(src_ip, src_mac, in_port):
    if src_ip not in db_ip_mac_port:
        db_ip_mac_port[src_ip] = {"mac": src_mac, "port": in_port}
        print(f"--- Veritabanı Güncellendi: {src_ip} -> MAC: {src_mac}, Port: {in_port} ---")
    else:
        existing_mac, existing_port = db_ip_mac_port[src_ip]["mac"], db_ip_mac_port[src_ip]["port"] 
        if existing_mac != src_mac or existing_port != in_port:
            db_ip_mac_port[src_ip] = {"mac": src_mac, "port": in_port}
            print(f"--- Veritabanı Güncellendi: {src_ip} -> MAC: {src_mac}, Port: {in_port} ---")




# Switch'ten gelen Packet-In mesajlarını dinleyen fonksiyon
def receive_packet_in(switch, p4info_helper):
    print(f"--- {switch.name} üzerinden paketler dinleniyor... ---")  
    while True:
        packet_in = switch.PacketIn()
        metadata = packet_in.metadata
        payload = packet_in.payload
        
        in_port = int.from_bytes(metadata[0].value, byteorder='big')
        pkt = Ether(payload)
        src_mac = pkt.src
        dst_mac = pkt.dst
        
        # print(pkt.show(dump=True))  #paket içeriğini detaylı şekilde göster
        if ARP in pkt:
            arp_pkt = pkt[ARP]
            src_ip = arp_pkt.psrc
            src_mac = arp_pkt.hwsrc
            
            # kaynağı öğren
            if src_ip not in db_ip_mac_port:
                print(f"--- [ARP Üzerinden Öğrenildi] {src_ip} -> Port: {in_port} ---")
                db_ip_mac_port[src_ip] = {"mac": src_mac, "port": in_port}
                write_ipv4_rule(switch, p4info_helper, src_ip, in_port, src_mac)

           # ARP tipine göre yönlendirme yap
             
        elif IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            # kural yaz
            if src_ip not in db_ip_mac_port:
                db_ip_mac_port[src_ip] = {"mac": src_mac, "port": in_port}
                print(f"--- Yeni Host Öğrenildi: {src_ip} ---")
                write_ipv4_rule(switch, p4info_helper, src_ip, in_port, src_mac)
                
            # paketi yönlendir
            if dst_ip in db_ip_mac_port:
                dst_port = db_ip_mac_port[dst_ip]["port"]
                send_packet_out(switch, dst_port, pkt)
            else: # bilinmeyen hedef IP'si
                discover_host(switch, p4info_helper, dst_ip, in_port, src_mac, src_ip)
                
                
...


if __name__ == '__main__':
    main()
...