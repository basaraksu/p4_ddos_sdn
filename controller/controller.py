import sys
import os
import time
import subprocess
from scapy.all import Ether, IP, ARP, TCP, UDP
import numpy as np
import joblib
import threading
import queue
from packet_in_thread import PacketInThread
from digest_thread import DigestThread
from feature_thread import FeatureThread
from ml_engine_thread import MLEngineThread
from csv_thread import CSVThread

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../../utils/'))

import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4.v1 import p4runtime_pb2

NUMOFPORTS = 3


class DDoSController:
    def __init__(self):
        self.p4info_file = "../build/ddos_detection.p4.p4info.txtpb"
        self.bmv2_json = "../build/ddos_detection.json"
        self.ip_mac_port_dict = {}  # IP-MAC-Port bilgilerini tutacak sözlük
        self.flow_stats_dict = {}  # Akış istatistiklerini tutacak sözlük
        self.active_ports = list(range(1, NUMOFPORTS + 1))  # Aktif port listesi
        self.window_duration = 5  # Özellik güncelleme periyodu (saniye cinsinden)
        self.idle_counter = 10  # Idle sayacı eşiği (periyot sayısı cinsinden)
        self.switch = None
        self.p4info_helper = None
        
        self.q_digest = queue.Queue()  # Digest verilerini tutacak kuyruk
        self.q_feature = queue.Queue()  # İşlenmiş özellikleri tutacak kuyruk
        
    ...
    

    def setup_switch(self):
        self.p4info_helper = p4runtime_lib.helper.P4InfoHelper(self.p4info_file)

        # Switch baglantisini kur
        self.switch = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0)

        self.switch.MasterArbitrationUpdate()
        # self.switch.SetForwardingPipelineConfig(
        #     p4info=self.p4info_helper.p4info,
        #     bmv2_json_file_path=self.bmv2_json)
        
        digest_entry = self.p4info_helper.buildDigestEntry(digest_name="flow_features_t")
        self.switch.WriteDigestEntry(digest_entry)
        print("--- Digest kaydi tamamlandi ---")
        
        print("P4 program yüklendi ve switch hazır!")
    ...    
    
        
    def run(self):
        self.setup_switch()
        #packet_in_thread = PacketInThread(self.switch, self)
        
        digest_thread = DigestThread(self.switch, self)
        feature_thread = FeatureThread(self.switch, self)
        ml_engine_thread = MLEngineThread(self.switch, self)
        csv_thread = CSVThread(self.switch, self)
        #packet_in_thread.start()
        digest_thread.start()
        #csv_thread.start()
        feature_thread.start()
        ml_engine_thread.start()
        
        # Ana thread
        while True:
            time.sleep(1)
            
    ...
