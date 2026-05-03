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
import pandas as pd
import threading


sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../../utils/'))

import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4.v1 import p4runtime_pb2

class DDoSController(threading.Thread):
    def __init__(self, name, switch_list, csv_file_name, daemon=True):
        super().__init__(daemon=daemon)
        self.name = name
        self.switch_list = switch_list
        self.csv_file_name = csv_file_name
        self.features_list_lock = threading.Lock()  # Veriye erişim için kilit
        
        
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
            switch_thread.start()
        pass
    
        
    def run(self):
        
        self.setup_switch_workers() # artık digest alınabilir.
        # switchlerin digest mesaları q_digest kuyruğuna gelmeye başlayacak.
        
        # feature threadi digest kuyruğunu dinleyebilir ve feature liste ekler
        feature_thread = FeatureThread(self)
        feature_thread.start()
        
        # ml engine threadi feature listesini dinleyebilir ve csv dosyasına yazabilir
        ml_engine_thread = MLEngineThread(self)
        ml_engine_thread.start()
        
        
        # Ana thread
        while True:
            time.sleep(1)
            
    ...
