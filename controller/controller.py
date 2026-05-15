import sys
import os
import time
from scapy.all import Ether, IP, ARP, TCP, UDP
import numpy as np
import threading
import queue
from feature_thread import FeatureThread
from ml_engine_thread import MLEngineThread
from switch_worker_thread import switchWorkerThread
from ban_manager_thread import BanManagerThread
import pandas as pd
import threading

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../blockchain/'))

from blockchain_node import BlockchainNode


sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../../utils/'))

import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4.v1 import p4runtime_pb2

class DDoSController(threading.Thread):
    def __init__(self, name, switch_list, csv_file_name, p2p_port, peers, controllers_in_network, daemon=True):
        super().__init__(daemon=daemon)
        self.name = name
        self.switch_list = switch_list
        self.switch_workers = []  # Her switch için ayrı bir worker thread'i olacak
        self.csv_file_name = csv_file_name
        self.features_list_lock = threading.Lock()  # Veriye erişim için kilit
        
        self.p2p_port = p2p_port
        self.peers = peers
        self.controllers_in_network = controllers_in_network
        self.ban_queue = queue.Queue() # ML motorunun IP'leri fırlatacağı kova
        self.banned_ips = set() # Banlanan IP'leri takip etmek için bir set
        
        # --- YENİ: BLOKZİNCİR DÜĞÜMÜNÜ BAŞLAT ---
        self.blockchain = BlockchainNode(
            node_id=self.name,
            host='127.0.0.1',
            port=self.p2p_port,
            peers=self.peers,
            controller=self  
        )
        
        
        self.p4info_file = "../build/ddos_detection.p4.p4info.txtpb"
        self.bmv2_json = "../build/ddos_detection.json"
        self.window_duration = 5  # Özellik güncelleme periyodu (saniye cinsinden)
        
        self.q_digest = queue.Queue()  # Digest verilerini tutacak kuyruk
        self.features_list = []  # İşlenmiş özellikleri geçici olarak tutacak liste
        
    ...
       
       
    def setup_switch_workers(self):
        for switch_info in self.switch_list:
            switch_thread = switchWorkerThread(
                switch_name=switch_info['name'],
                grpc_port=switch_info['grpc_port'],
                device_id=switch_info['device_id'],
                controller=self
            )
            self.switch_workers.append(switch_thread)
            switch_thread.start()
    
    
    def execute_drop_rule(self, malicious_ip):
        """ ML'den veya Ağdan gelen Saldırgan IP'yi donanım seviyesinde bloklar """
        if malicious_ip not in self.banned_ips:
            print(f"[{self.name}] 🛡️ P4 KASLARI AKTİF: {malicious_ip} için DROP kuralı yazılıyor...")

            # Bu kontrolcüye bağlı tüm P4 switch'leri (worker'ları) dön
            for worker in self.switch_workers:
                try:
                    # SENİN ŞABLONUN BİREBİR UYARLANMIŞ HALİ:
                    table_entry = worker.p4info_helper.buildTableEntry(
                        table_name="MyIngress.ipv4_acl",  # Yönlendirme değil, Filtreleme (ACL) tablosu
                        match_fields={
                            "hdr.ipv4.srcAddr": malicious_ip # KAYNAK IP'yi yakala!
                        },
                        action_name="MyIngress.drop",     # Forward değil, Drop aksiyonu
                        action_params={}                  # Drop aksiyonu port veya MAC istemez, içi boş kalır
                    )
                    
                    # Kuralı switch'e yaz!
                    worker.switch.WriteTableEntry(table_entry)
                    print(f"[{self.name}] -> {worker.switch_name} switch'ine DROP kuralı donanımdan çakıldı!")
                    self.banned_ips.add(malicious_ip)
                except Exception as e:
                    # Switch o an kapalıysa bile sistem çökmez, log yazar devam eder
                    print(f"[{self.name}] -> {worker.switch_name} kural yazma hatası: {e}")
    

    def run(self):
        
        self.setup_switch_workers() # artık digest alınabilir.
        # switchlerin digest mesaları q_digest kuyruğuna gelmeye başlayacak.
        
        # feature threadi digest kuyruğunu dinleyebilir ve feature liste ekler
        feature_thread = FeatureThread(self)
        feature_thread.start()
        
        # ml engine threadi feature listesini dinleyebilir ve csv dosyasına yazabilir
        ml_engine_thread = MLEngineThread(self)
        ml_engine_thread.start()
        
        # ban manager threadi ban kuyruğunu dinleyebilir ve saldırgan IP'leri banlayabilir
        ban_manager_thread = BanManagerThread(self)
        ban_manager_thread.start()
        
        
        
        # Ana thread
        while True:
            time.sleep(1)
            
    ...
