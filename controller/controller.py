import sys
import os
import time
import subprocess
from scapy.all import Ether, IP, ARP, TCP, UDP
import numpy as np
import joblib

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
        self.ip_mac_port_dict = {}  # IP-MAC-Port bilgilerini tutacak sözlük
        self.flow_stats_dict = {}  # Akış istatistiklerini tutacak sözlük
        self.features_dict = {}  # Akışlara ait özellik listelerini tutacak sözlük
        self.active_ports = [1, 2, 3]  # Aktif port listesi
        self.srates_dict = {}
        self.window_duration = 5  # Özellik güncelleme periyodu (saniye cinsinden)
        self.idle_counter = 10  # Idle sayacı eşiği (periyot sayısı cinsinden)
        self.switch = None
        self.p4info_helper = None
        self.model_data = joblib.load('../ddos_xgboost_model.pkl')
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
    

    def send_packet_out(self, egress_port, pkt=0):
        payload = bytes(pkt)
        metadatas = [
            {
                "value": egress_port,
                "bitwidth": 16
            }
            
        ]

        try:
            self.switch.PacketOut(payload, metadatas)
            #print(f"--- [Packet-Out] Port {egress_port} BASARILI! ---")
        except Exception as e:
            #print(f"!!! Packet-Out hala basarisiz: {e}")
            pass
    ...
    
    
    def send_register_request(self, flow_id):
        #print(f"--- Flow ID {flow_id} icin register sorgusu gonderiliyor... ---")
        REGISTER_REQUEST = 1  # Özel bir değerle register sorgusu olduğunu belirtebilirsin
        # 1. Boş bir paket (Sadece switch içinde dolaşacak bir taşıyıcı)
        probe_pkt = Ether(src="00:00:00:00:00:00", dst="00:00:00:00:00:00", type=0x8888)
        payload = bytes(probe_pkt)

        # 2. Metadata listesi (Sıralama P4Info'daki header sırasıyla aynı olmalı)
        metadatas = [
            {
                "value": 511,       # Egress port: 511 (Sorgu işareti)
                "bitwidth": 16
            },
            {
                "value": flow_id,   # Sorgulanan Akış ID'si
                "bitwidth": 32
            },
            {
                "value": REGISTER_REQUEST,   # Özel bir değerle ilk_seen ve last_seen için de bilgi gönderebilirsin
                "bitwidth": 32
            }
        ]

        try:
            self.switch.PacketOut(payload, metadatas)
        except Exception as e:
            pass
    ...
    

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
    
    
    def write_flow_tracker_rule(self, flow_id):
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.flow_tracker",
            match_fields={
                "meta.flow_id": flow_id
            },
            action_name="MyIngress.tracked_flow",
            action_params={}
        )
        self.switch.WriteTableEntry(table_entry)
    ...
        

    def update_ip_mac_port_dict(self, src_ip, src_mac, in_port):
        if src_ip not in self.ip_mac_port_dict:
            self.ip_mac_port_dict[src_ip] = {"mac": src_mac, "port": in_port}
            #print(f"--- Veritabani Guncellendi: {src_ip} -> MAC: {src_mac}, Port: {in_port} ---")
        else:
            existing_mac = self.ip_mac_port_dict[src_ip]["mac"]
            existing_port = self.ip_mac_port_dict[src_ip]["port"]
            if existing_mac != src_mac or existing_port != in_port:
                self.ip_mac_port_dict[src_ip] = {"mac": src_mac, "port": in_port}
                #print(f"--- Veritabani Guncellendi: {src_ip} -> MAC: {src_mac}, Port: {in_port} ---")
    ...


    def add_flow_stats_dict(self, flow_id, ips, ports, proto, first_seen, last_seen):
        if flow_id not in self.flow_stats_dict:
            self.flow_stats_dict[flow_id] = {
            'src_ip': ips[0],
            'dst_ip': ips[1],
            'proto': proto,
            'dst_port': ports[1],
            'tot_pkts': 0,
            'prev_fwd_pkts': 0,
            'prev_bwd_pkts': 0,
            'first_seen': first_seen,   
            'last_seen': last_seen,
            'dur': last_seen - first_seen,
            'max_dur': last_seen - first_seen,
            'is_idle': False,
            'idle_counter': self.idle_counter  # Örneğin, 2 periyot boyunca idle kalırsa silinecek
        }
    ...
    
    
    def update_flows_stats_dict(self):
        while True:
            time.sleep(self.window_duration)  # Belirtilen süre bekle
            if self.flow_stats_dict == {}:
                print("--- Flow Stats Dict boş, güncelleme atlanıyor... ---")
                continue
            for flow_id, flow_data in list(self.flow_stats_dict.items()):
                if flow_data['is_idle'] == False and 'current_registers' in flow_data:
                    print(f"--- Flow ID {flow_id} icin flow_stats_dict guncelleniyor... ---")
                    print(flow_data) 
        
    ...
    
    
    def generate_feature(self, flow_id, current_registers):
        if flow_id in self.flow_stats_dict:
            flow_data = self.flow_stats_dict[flow_id]
            flow_data['tot_pkts'] = current_registers['current_fwd_pkts'] + current_registers['current_bwd_pkts']
            if flow_data['last_seen'] == current_registers['last_seen']:
                flow_data['is_idle'] = True
                srate = 0
                drate = 0
                dur = 0       
            else:
                flow_data['is_idle'] = False
                flow_data['idle_counter'] = self.idle_counter  # Aktif olduğu sürece idle counter'ı sıfırla
                delta_time = current_registers['last_seen'] - current_registers['first_seen']
                delta_time /= 1e6 # Mikro saniyeyi saniyeye çevir
                delta_time = int(delta_time) 
                delta_time %= self.window_duration # Eğer zaman aşımı nedeniyle büyük bir fark oluşursa, bunu düzeltmek için mod alma işlemi yapabiliriz.
                if delta_time == 0: delta_time = 5
                
                print(f"--- Flow ID {flow_id}: delta_time = {delta_time} ---")
                
                delta_fwd = current_registers['current_fwd_pkts'] - flow_data['prev_fwd_pkts']
                print(f"--- Flow ID {flow_id}: delta_fwd = {delta_fwd} ---")
                
                
                srate = (current_registers['current_fwd_pkts'] - flow_data['prev_fwd_pkts']) / delta_time
                drate = (current_registers['current_bwd_pkts'] - flow_data['prev_bwd_pkts']) / delta_time
                dur = flow_data['dur'] + delta_time
            
            dst_ip = flow_data['dst_ip']
            proto = flow_data['proto']
            
            TnP_PDstIP = sum([f['prev_fwd_pkts'] for f in self.flow_stats_dict.values() if f['dst_ip'] == dst_ip])
            
            flow_data['dur'] = dur 
            flow_data['max_dur'] = max(flow_data['max_dur'], dur) 
            
            return {
                'fwd_pkts': current_registers['current_fwd_pkts'],
                'pkts': flow_data['tot_pkts'],
                'srate': srate,
                'drate': drate,
                # 'TnP_PDstIP': TnP_PDstIP, => sonradan kümülatif olarak ekleyeceğiz
                'dur': dur,
                'max_dur': flow_data['max_dur'],
                'proto': proto
            } 
        ...
    ...
       
    
    def prepare_features(self):
        # Features: ['Pkts', 'Srate', 'Drate', 'TnP_PDstIP', 'Dur', 'Max', 'proto_number']
        for key in list(self.features_dict.keys()):
            
            dst_ip = self.flow_stats_dict[key]['dst_ip']
            flow_ids = [k for k, f in list(self.flow_stats_dict.items()) if self.flow_stats_dict[k]['dst_ip'] == dst_ip]
            TnP_PDstIP = sum([self.features_dict[k]['fwd_pkts'] if k in self.features_dict else 0 for k in flow_ids])
            
            self.features_dict[key]['model_features'] = np.array([
                self.features_dict[key]['pkts'], 
                self.features_dict[key]['srate'],
                self.features_dict[key]['drate'],
                TnP_PDstIP,
                #self.features_dict[key]['dur'],
                self.features_dict[key]['max_dur'],
                self.features_dict[key]['proto']
            ])
            
        
    ...
    
    
    def read_registers(self):
        while True:
            time.sleep(self.window_duration) # Belirtilen süre bekle
            for flow_id in list(self.flow_stats_dict.keys()):
                flow_data = self.flow_stats_dict[flow_id]
                if flow_data['is_idle'] == True:
                    flow_data['idle_counter'] -= 1 
                    if flow_data['idle_counter'] <= 0:
                        self.untrack_flow(flow_id)
                        continue
                self.send_register_request(flow_id)
    ...
    
    
    def handle_register_response(self, flow_id, current_registers):
        features=self.generate_feature(flow_id, current_registers)
        self.features_dict[flow_id] = features
        #self.update_flows_stats_dict(flow_id, current_registers)
    ...
    
    
    def untrack_flow(self, flow_id):
        if flow_id not in self.flow_stats_dict:
            return
        self.switch.DeleteTableEntry(self.p4info_helper.buildTableEntry(
            table_name="MyIngress.flow_tracker",
            match_fields={
                "meta.flow_id": flow_id
            }
        ))
        del self.features_dict[flow_id]
        del self.flow_stats_dict[flow_id]
        print(f"--- Flow ID {flow_id} izlemeyi durduruldu ve veriler silindi. ---")
    ...
    
    
    def receive_packet_in(self):
        REGISTER_RESPONSE = 1
        print(f"--- {self.switch.name} uzerinden paketler dinleniyor... ---")
        while True:
            packet_in = self.switch.PacketIn()
            metadata = packet_in.metadata
            payload = packet_in.payload

            
            reason_code = int.from_bytes(metadata[1].value, byteorder='big')
            #print("--- Packet-In Geldi: Reason Code =", reason_code, "---")
            
            if reason_code == REGISTER_RESPONSE: # register sorgularindan gelen Packet-In mesajları
                fid = int.from_bytes(metadata[2].value, byteorder='big')
                fwd_count = int.from_bytes(metadata[5].value, byteorder='big')
                bwd_count = int.from_bytes(metadata[6].value, byteorder='big')
                first_seen = int.from_bytes(metadata[3].value, byteorder='big')
                last_seen = int.from_bytes(metadata[4].value, byteorder='big')
                current_registers= {
                    'current_fwd_pkts': fwd_count,
                    'current_bwd_pkts': bwd_count,
                    'first_seen': first_seen,
                    'last_seen': last_seen
                }
                #print(f"--- Register Response Geldi: Flow ID {fid}, fwd_count: {fwd_count}, bwd_count: {bwd_count}, first_seen: {first_seen}, last_seen: {last_seen} ---")
                #self.handle_register_response(fid, current_registers)
                
                self.flow_stats_dict[fid]['current_registers'] = current_registers
                continue
            
            in_port = int.from_bytes(metadata[0].value, byteorder='big')
            pkt = Ether(payload)
            src_mac = pkt.src

            if ARP in pkt:
                arp_pkt = pkt[ARP]
                src_ip = arp_pkt.psrc
                src_mac = arp_pkt.hwsrc

                if src_ip not in self.ip_mac_port_dict:
                    #print(f"--- [ARP Uzerinden Ogrenildi] {src_ip} -> Port: {in_port} ---")
                    self.update_ip_mac_port_dict(src_ip, src_mac, in_port)
                    self.write_ipv4_rule(src_ip, in_port, src_mac)

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
                
                
                if flow_id not in self.flow_stats_dict:
                    first_seen = int.from_bytes(metadata[3].value, byteorder='big') # Dikkat
                    last_seen = int.from_bytes(metadata[4].value, byteorder='big') # Dikkat
                    self.add_flow_stats_dict(flow_id, ips, ports, proto, first_seen, last_seen)
                    self.write_flow_tracker_rule(flow_id)

                if src_ip not in self.ip_mac_port_dict:
                    #print(f"--- Yeni Host Ogrenildi: {src_ip} ---")
                    self.update_ip_mac_port_dict(src_ip, src_mac, in_port)
                    self.write_ipv4_rule(src_ip, in_port, src_mac)

                if dst_ip in self.ip_mac_port_dict:
                    dst_port = self.ip_mac_port_dict[dst_ip]["port"]
                    self.send_packet_out(dst_port, pkt)
                else:
                    self.discover_host(dst_ip, in_port, src_mac, src_ip)
    ...
    
    
    def model_engine(self, features):
        model = self.model_data['model']
        self.prepare_features()
        for flow_id, feature_data in list(self.features_dict.items()):
            if self.flow_stats_dict[flow_id]['is_idle'] == True:
                continue
            print(f"\n--- Flow ID {flow_id}: features: {feature_data['model_features']} ---")
        
            prediction = model.predict(feature_data['model_features'].reshape(1, -1))
            proba = model.predict_proba(feature_data['model_features'].reshape(1, -1))[:, 1][0]
            if prediction[0] == 1:  # Eğer saldırı tespit edilirse
                print(f"--- DDoS Saldırısı Tespit Edildi! Flow ID: {flow_id} Saldırı Olasılığı: {proba} ---")
            else:
                print(f"--- Flow ID {flow_id} temiz görünüyor. Saldırı Olasılığı: {proba} ---")
    ...
    
    
    def print_features(self):
        for flow in list(self.features_dict.keys()):
                flow_data = self.features_dict.get(flow, {})
                if not flow_data:       
                    continue

                # İlk satırda tablo başlığı yazdır
                if flow == list(self.features_dict.keys())[0]:
                    print("\n{:<10} {:>10} {:>10} {:>10} {:>10} {:>8}".format(
                        "Flow ID", "SRate", "DRate", "Dur", "MaxDur", "Proto"
                    ))
                    print("-" * 64)

                print("{:<10} {:>10.2f} {:>10.2f} {:>10.2f} {:>10.2f} {:>8}".format(
                    flow,
                    flow_data.get("srate", 0),
                    flow_data.get("drate", 0),
                    flow_data.get("dur", 0),
                    flow_data.get("max_dur", 0),
                    flow_data.get("proto", 0),
                ))
    ...
        
        
    def run(self):
        self.setup_switch()

        # Packet-In ve Digest mesajlarını dinlemek için ayrı threadler başlat
        import threading
        packet_in_thread = threading.Thread(target=self.receive_packet_in, daemon=True)
        
        reading_thread = threading.Thread(target=self.read_registers, daemon=True)
        updating_thread = threading.Thread(target=self.update_flows_stats_dict, daemon=True)



        packet_in_thread.start()
        reading_thread.start()
        updating_thread.start()
        # Ana thread
        while True:
            pass
            #time.sleep(self.window_duration)  # Belirli aralıklarla özellikleri yazdır
            
            #self.print_features()
            #self.model_engine(self.features_dict)
    ...



def main():
    controller = DDoSController()
    controller.run()
...


if __name__ == '__main__':
    main()
...