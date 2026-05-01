from scapy.all import *
import threading
import time
import os
import pandas as pd
import warnings
# import joblib # ML için açılacak

warnings.filterwarnings("ignore")  # Özellikle ML modelinden gelen uyarıları gizle

class MLEngineThread(threading.Thread):
    def __init__(self, switch, controller, daemon=True):
        super().__init__(daemon=daemon)
        self.switch = switch
        self.controller = controller
        # self.model = joblib.load('../models/ddos_rf_model.pkl')
        # self.scaler = joblib.load('../models/robust_scaler.pkl')
        
    def run(self):
        print(f"--- {self.switch.name} ML Engine basladi. 5 saniyelik pencerelerle dinleniyor... ---")
        colnames = ['flow_id', 'firstIp', 'secondIp', 'firstPort', 'secondPort', 
                    'fwd_count', 'bwd_count', 'N_IN_Conn_P_DstIP', 'TnP_PDstIP', 
                    'Srate', 'Drate', 'Dur', 'Bytes', 'proto_number']
                
        while True:
            time.sleep(5) # 5 saniyelik Micro-Batch penceresi
            
            # --- RACE CONDITION (VERİ KAYBI) ÇÖZÜMÜ ---
            # O anki listeyi datas içine al ve controller.features_list'e anında boş liste ata.
            # Bu işlem saniyenin milyarda biri sürer, FeatureThread yeni listeye yazmaya devam eder, veri kaybolmaz.
            datas = self.controller.features_list
            self.controller.features_list = [] 
            
            if not datas:
                continue
            
            # Pandas DF oluşturma
            df = pd.DataFrame(datas, columns=colnames)
            
            # --- KÜMÜLATİF HESAPLAMALAR ---
            # 1. Hedef IP'ye gelen benzersiz akış/bağlantı sayısı
            df['N_IN_Conn_P_DstIP'] = df.groupby('secondIp')['flow_id'].transform('nunique')
            
            # 2. Hedfe gelen toplam paket sayısı
            df['TnP_PDstIP'] = df.groupby('secondIp')['fwd_count'].transform('sum')
            
            # CSV'ye yazma
            filename = f'features_{self.switch.name}.csv'
            is_file_new = os.path.exists(filename)
            df.to_csv(filename, mode='a', header=not is_file_new, index=False)
            
            print(f"--- [ML ENGINE] {len(df)} adet akis islendi ve CSV'ye yazildi. ---")
            
            # --- ML TAHMİNİ (GELECEK İÇİN HAZIRLIK) ---
            # features_for_model = df.drop(columns=['flow_id', 'firstIp', 'secondIp', 'firstPort', 'secondPort'])
            # scaled_features = self.scaler.transform(features_for_model)
            # predictions = self.model.predict(scaled_features)
            # df['is_ddos'] = predictions
            # DDOS ise kontrolcüye haber ver (Örn: self.controller.block_ip(df[df['is_ddos'] == 1]['firstIp']))

            # Memory serbest bırakma
            del df 
            del datas