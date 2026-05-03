from scapy.all import *
import threading
import time
import queue
import pandas as pd
from helper import write_to_csv
import ipaddress

class FeatureThread(threading.Thread):
    def __init__(self, controller, daemon=True):
        super().__init__(daemon=daemon)
        self.controller = controller
        
        
    def run(self):
        print(f"--- {self.controller.name} Feature verileri dinleniyor... ---")
        while True:
            try:
                # Feature mesajını al
                raw_data = self.controller.q_digest.get()

                if not raw_data:
                    continue
                
                # digestten gelen raw_data
                # flow_id, first_ip, second_ip, src_port, dst_port, protocol, fwd_count, bwd_count, packet_size_sum, duration, iat_sum, iat_sum_square, min_iat, max_iat
                
                colnames = ['flow_id','switch_name','controller_name', 'firstIp', 'secondIp', 'firstPort', 'secondPort', 'fwd_count', 'bwd_count', 'N_IN_Conn_P_DstIP', 'TnP_PDstIP', 'Srate', 'Drate', 'Dur', 'Bytes', 'proto_number']
                
                dur_in_seconds = raw_data['duration'] / 1000000.0
                
                # Özellikleri hesapla
                processed_data = {
                    'flow_id': raw_data['flow_id'],
                    'switch_name': raw_data['switch_name'],
                    'controller_name': self.controller.name,
                    'first_ip': str(ipaddress.IPv4Address(raw_data['first_ip'])),
                    'second_ip': str(ipaddress.IPv4Address(raw_data['second_ip'])),
                    'firstPort': raw_data['first_port'],
                    'secondPort': raw_data['second_port'],
                    'fwd_count': raw_data['fwd_count'],
                    'bwd_count': raw_data['bwd_count'],
                    'Srate': raw_data['fwd_count'] / dur_in_seconds if dur_in_seconds > 0 else 0,
                    'Drate': raw_data['bwd_count'] / dur_in_seconds if dur_in_seconds > 0 else 0,
                    'Dur': dur_in_seconds,
                    'Bytes': raw_data['packet_size_sum'],
                    'proto_number': raw_data['protocol']
                }
                

                features = [
                        processed_data['flow_id'],
                        processed_data['switch_name'],
                        processed_data['controller_name'],
                        processed_data['first_ip'],
                        processed_data['second_ip'],
                        processed_data['firstPort'],
                        processed_data['secondPort'], 
                        processed_data['fwd_count'],
                        processed_data['bwd_count'],
                        processed_data['Srate'],
                        processed_data['Drate'],
                        processed_data['Dur'],
                        processed_data['Bytes'],
                        processed_data['proto_number']
                    ]
                
                with self.controller.features_list_lock:
                    self.controller.features_list.append(features)
                # if len(self.controller.features_list) >= self.controller.BATCH_SIZE:  # Belirli bir sayıya ulaşıldığında CSV'ye yaz
                #     write_to_csv(self.controller.features_list, colnames)
                #     self.controller.features_list.clear()  # Listeyi temizle
                #print(f"--- Feature alindi: {processed_data['flow_id']} ---")
            
            except Exception as e:
                print(f"Feature Extraction Hatası: {e}")
                time.sleep(1) # Hata durumunda döngüyü yavaşlat
    ...