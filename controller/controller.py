import sys
import os
import time
from scapy.all import Ether, IP, ARP

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../../utils/'))

import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4.v1 import p4runtime_pb2


class DDoSController:
    def __init__(self):
        self.p4info_file = "../build/ddos_detection.p4.p4info.txtpb"
        self.bmv2_json = "../build/ddos_detection.json"
        self.db_ip_mac_port = {}  # IP-MAC-Port bilgilerini tutacak sözlük
        self.active_ports = [1, 2, 3]  # Aktif port listesi
        self.switch = None
        self.p4info_helper = None
    ...
    

    def setup_switch(self):
        self.p4info_helper = p4runtime_lib.helper.P4InfoHelper(self.p4info_file)

        # Switch baglantisini kur
        self.switch = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0)

        self.switch.MasterArbitrationUpdate()
        self.switch.SetForwardingPipelineConfig(
            p4info=self.p4info_helper.p4info,
            bmv2_json_file_path=self.bmv2_json)
        
        digest_entry = self.p4info_helper.buildDigestEntry(digest_name="flow_features_t")
        self.switch.WriteDigestEntry(digest_entry)
        print("--- Digest kaydi tamamlandi ---")
        
        print("P4 program yüklendi ve switch hazır!")
    ...    
    

    def discover_host(self, target_ip, ingress_port, sender_mac, sender_ip):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=sender_mac) / \
              ARP(op=1, hwsrc=sender_mac, psrc=sender_ip, pdst=target_ip)

        # Paketin geldiği port haric tüm aktif portlara gönder
        for port in self.active_ports:
            if port != ingress_port:
                self.send_packet_out(port, pkt)
    ...
    

    def send_packet_out(self, egress_port, pkt):
        payload = bytes(pkt)
        metadatas = [
            {
                "value": egress_port,
                "bitwidth": 16
            }
        ]

        try:
            self.switch.PacketOut(payload, metadatas)
            print(f"--- [Packet-Out] Port {egress_port} BASARILI! ---")
        except Exception as e:
            print(f"!!! Packet-Out hala basarisiz: {e}")
    ...
    

    # Switch'e yeni bir kural yazmak icin kullanilan method
    def write_ipv4_rule(self, ip_addr, port, mac_addr):
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (ip_addr, 32)
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "port": port,
                "dstAddr": mac_addr
            })
        self.switch.WriteTableEntry(table_entry)
    ...
        

    def update_db(self, src_ip, src_mac, in_port):
        if src_ip not in self.db_ip_mac_port:
            self.db_ip_mac_port[src_ip] = {"mac": src_mac, "port": in_port}
            print(f"--- Veritabani Guncellendi: {src_ip} -> MAC: {src_mac}, Port: {in_port} ---")
        else:
            existing_mac = self.db_ip_mac_port[src_ip]["mac"]
            existing_port = self.db_ip_mac_port[src_ip]["port"]
            if existing_mac != src_mac or existing_port != in_port:
                self.db_ip_mac_port[src_ip] = {"mac": src_mac, "port": in_port}
                print(f"--- Veritabani Guncellendi: {src_ip} -> MAC: {src_mac}, Port: {in_port} ---")
    ...


    # Switch'ten gelen Packet-In mesajlarini dinleyen method
    def receive_packet_in(self):
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

                if src_ip not in self.db_ip_mac_port:
                    print(f"--- [ARP Uzerinden Ogrenildi] {src_ip} -> Port: {in_port} ---")
                    self.update_db(src_ip, src_mac, in_port)
                    self.write_ipv4_rule(src_ip, in_port, src_mac)

            elif IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                if src_ip not in self.db_ip_mac_port:
                    print(f"--- Yeni Host Ogrenildi: {src_ip} ---")
                    self.update_db(src_ip, src_mac, in_port)
                    self.write_ipv4_rule(src_ip, in_port, src_mac)

                if dst_ip in self.db_ip_mac_port:
                    dst_port = self.db_ip_mac_port[dst_ip]["port"]
                    self.send_packet_out(dst_port, pkt)
                else:
                    self.discover_host(dst_ip, in_port, src_mac, src_ip)
    ...   

    
    def receive_digest(self):
        print(f"--- {self.switch.name} Digest verileri dinleniyor... ---")
        while True:
            digest_msg = self.switch.Digest()

            for item in digest_msg.data:
                # P4 struct sırasına göre üyeleri alıyoruz
                members = item.struct.members
                
                # Her bir alanı bit genişliğine göre integer'a çevir
                stats = {
                    "flow_id":      int.from_bytes(members[0].bitstring, 'big'),
                    "flow_iat_max": int.from_bytes(members[1].bitstring, 'big'),
                    "flow_iat_sum": int.from_bytes(members[2].bitstring, 'big'),
                    "fwd_count":    int.from_bytes(members[3].bitstring, 'big'),
                    "bwd_count":    int.from_bytes(members[4].bitstring, 'big'),
                    "packet_count": int.from_bytes(members[5].bitstring, 'big'),
                    "flow_duration": int.from_bytes(members[6].bitstring, 'big'),
                    "fwd_header_len": int.from_bytes(members[7].bitstring, 'big'),
                    "bwd_header_len": int.from_bytes(members[8].bitstring, 'big'),
                    "bwd_iat_tot": int.from_bytes(members[9].bitstring, 'big'),
                    "fwd_iat_min": int.from_bytes(members[10].bitstring, 'big')    
                }

                self.process_stats(stats)
    ...
    
    
    def process_stats(self, stats):
        # BMv2 Mikrosaniye (us) kullandığı için:
        duration_us = stats['flow_duration']
        duration_sec = duration_us / 1e6
        
        # Modelin beklediği özelliklerin hesaplanması
        flow_pkts_s = stats['packet_count'] / duration_sec if duration_sec > 0 else 0
        bwd_pkts_s = stats['bwd_count'] / duration_sec if duration_sec > 0 else 0
        # IAT Mean: Toplam IAT / (Paket sayısı - 1) -> Dataset standardı budur
        iat_mean = stats['flow_iat_sum'] / (stats['packet_count'] - 1) if stats['packet_count'] > 1 else 0

        print("\n" + "="*40)
        print(f"[FLOW ID: {stats['flow_id']}]")
        print(f"  - Tot Fwd Pkts:    {stats['fwd_count']}")
        print(f"  - Fwd Header Len:  {stats['fwd_header_len']}")
        print(f"  - Bwd Header Len:  {stats['bwd_header_len']}")
        print(f"  - Flow Duration:   {duration_us}") # Dataset mikrosaniye ise us olarak kalsın
        print(f"  - Flow IAT Max:    {stats['flow_iat_max']}")
        print(f"  - Flow IAT Mean:   {iat_mean:.2f}")
        print(f"  - Fwd IAT Min:     {stats['fwd_iat_min']}")
        print(f"  - Bwd IAT Tot:     {stats['bwd_iat_tot']}")
        print(f"  - Flow Pkts/s:     {flow_pkts_s:.2f}")
        print(f"  - Bwd Pkts/s:      {bwd_pkts_s:.2f}")
        print("="*40 + "\n")
    ...    
        
    def run(self):
        self.setup_switch()

        # Packet-In ve Digest mesajlarını dinlemek için ayrı threadler başlat
        import threading
        packet_in_thread = threading.Thread(target=self.receive_packet_in, daemon=True)
        digest_thread = threading.Thread(target=self.receive_digest, daemon=True)

        packet_in_thread.start()
        digest_thread.start()

        # Ana thread
        while True:
            time.sleep(1)
    ...
...


def main():
    controller = DDoSController()
    controller.run()
...


if __name__ == '__main__':
    main()
...