from scapy.all import *
import threading
import time
import queue
import pandas as pd

class FeatureThread(threading.Thread):
    def __init__(self, switch, controller, daemon=True):
        super().__init__(daemon=daemon)
        self.switch = switch
        self.controller = controller
        
        
    def run(self):
        print(f"--- {self.switch.name} Feature verileri dinleniyor... ---")
        while True:
            try:
                # Feature mesajını al
                raw_data = self.controller.q_digest.get()

                if not raw_data:
                    continue
                
                # raw_data
                # ['flow_id', 'fwd_count', 'bwd_count', 'duration', 'packet_size_sum', 
                # 'min_packet_size', 'max_packet_size', 'iat_sum', 'iat_sum_square', 
                # 'min_iat', 'max_iat', 'protocol']
                
                # Özellik Sırası:
                # ['flow iat min', 'flow iat max', 'flow iat mean', 'flow iat std', 
                # 'rate_ratio', 'protocol', 'max packet length', 'min packet length', 
                # 'packet length mean']
                
                colnames = ['flow iat min', 'flow iat max', 'flow iat mean', 'flow iat std', 
                            'rate_ratio', 'max packet length', 'min packet length', 
                            'packet length mean']
                
                iat_count = raw_data['fwd_count'] + raw_data['bwd_count'] - 1
                
                variance_input = (raw_data['iat_sum_square'] / iat_count) - (raw_data['iat_sum'] / iat_count) ** 2 if iat_count > 0 else 0  

                # Eğer sonuç çok küçük bir negatif sayıysa 0 kabul et
                safe_variance = max(0, variance_input)
                
                # Özellikleri hesapla
                processed_data = {
                    'flow_id': raw_data['flow_id'],
                    'flow_iat_min': raw_data['min_iat'],
                    'flow_iat_max': raw_data['max_iat'],
                    'flow_iat_mean': raw_data['iat_sum'] / iat_count if iat_count > 0 else 0,
                    'flow_iat_std': safe_variance ** 0.5,
                    'rate_ratio': (raw_data['fwd_count'] / raw_data['bwd_count']) if raw_data['bwd_count'] > 0 else raw_data['fwd_count'] / 5,
                    #protocol': raw_data['protocol'],
                    'max_packet_length': raw_data['max_packet_size'],
                    'min_packet_length': raw_data['min_packet_size'],
                    'packet_length_mean': raw_data['packet_size_sum'] / (raw_data['fwd_count'] + raw_data['bwd_count']) if (raw_data['fwd_count'] + raw_data['bwd_count']) > 0 else 0
                }
                
                feature = {
                    'flow_id': processed_data['flow_id'],
                    'features': [
                        processed_data['flow_iat_min'],
                        processed_data['flow_iat_max'],
                        processed_data['flow_iat_mean'],
                        processed_data['flow_iat_std'],
                        processed_data['rate_ratio'],
                        #processed_data['protocol'],
                        processed_data['max_packet_length'],
                        processed_data['min_packet_length'],
                        processed_data['packet_length_mean']
                    ]
                }
                
                feature['features'] = pd.DataFrame([feature['features']], columns=colnames)
                
                # print(f"--- Feature alindi: {feature['flow_id']} ---")
                
                
                try:
                    self.controller.q_feature.put(feature, block=False)
                except:
                    # Kuyruk doluysa en eski veriyi atmak için mantık eklenebilir
                    pass            
            except Exception as e:
                print(f"Feature Extraction Hatası: {e}")
                time.sleep(1) # Hata durumunda döngüyü yavaşlat
    ...