from scapy.all import *
import threading
import time
import os
import pandas as pd
import warnings
import joblib 

warnings.filterwarnings("ignore")  # Özellikle ML modelinden gelen uyarıları gizle

class MLEngineThread(threading.Thread):
    def __init__(self, controller, daemon=True):
        super().__init__(daemon=daemon)
        self.controller = controller
        self.model = joblib.load('../models/my_model.pkl')
        
    def run(self):
        print(f"--- {self.controller.name} ML Engine basladi. 5 saniyelik pencerelerle dinleniyor... ---")
        colnames = ['flow_id', 'switch_name', 'controller_name', 'firstIp', 'secondIp', 'firstPort', 'secondPort', 
                    'fwd_count', 'bwd_count', 'Srate', 'Drate', 'Dur', 'Bytes', 'proto_number']
                
        while True:
            time.sleep(5) # 5 saniyelik Micro-Batch penceresi
            
            # --- RACE CONDITION (VERİ KAYBI) ÇÖZÜMÜ ---
            # O anki listeyi datas içine al ve controller.features_list'e anında boş liste ata.
            # Bu işlem saniyenin milyarda biri sürer, FeatureThread yeni listeye yazmaya devam eder, veri kaybolmaz.
            with self.controller.features_list_lock:
                datas = list(self.controller.features_list) # list() ile gerçek bir kopya yaratıyoruz!
                self.controller.features_list.clear() # Orijinal listeyi güvenle boşaltıyoruz.
            
            if not datas:
                continue
            
            # Pandas DF oluşturma
            df = pd.DataFrame(datas, columns=colnames)
            
            # --- SİMETRİK KÜMÜLATİF HESAPLAMALAR ---

            # 1. Tüm IP'lerin (hem first hem second) toplam benzersiz bağlantılarını hesaplayalım
            # Önce IP bazlı bir "harita" oluşturuyoruz
            all_conns = pd.concat([
                df[['firstIp', 'secondIp']].rename(columns={'firstIp': 'IP', 'secondIp': 'Peer'}),
                df[['secondIp', 'firstIp']].rename(columns={'secondIp': 'IP', 'firstIp': 'Peer'})
            ])

            # Her IP için kaç tane benzersiz 'Peer' (eş) olduğunu bulalım
            conn_counts = all_conns.groupby('IP')['Peer'].nunique().to_dict()

            # 2. Şimdi bu gerçek değerleri ana tablomuza geri yazalım
            df['N_Conn_P_FirstIP'] = df['firstIp'].map(conn_counts).fillna(0)
            df['N_Conn_P_SecondIP'] = df['secondIp'].map(conn_counts).fillna(0)
            
            # # 2. Hedfe gelen toplam paket sayısı
            # df['TnP_P_SecondIP'] = df.groupby('secondIp')['fwd_count'].transform('sum')
            
            df['Avg_Packet_Size'] = df['Bytes'] / (df['fwd_count'] + df['bwd_count'] + 1e-6)
            
            # # CSV'ye yazma
            # filename = f'../data/{self.controller.csv_file_name}'
            # is_file_new = os.path.exists(filename)
            # df.to_csv(filename, mode='a', header=not is_file_new, index=False)
            
            #print(f"--- [ML ENGINE] {len(df)} adet akis islendi ve CSV'ye yazildi. ---")
            
           # --- ML TAHMİNİ VE SAVUNMA TETİKLEME ---
            # Modelin eğitilirken görmediği kimlik sütunlarını çıkarıyoruz
            features_for_model = df.drop(columns=['flow_id', 'firstIp', 'switch_name', 'controller_name', 'secondIp', 'firstPort', 'secondPort'])
            
            # Tahminleri yap ve DataFrame'e ekle (0: Normal, 1: DDoS)
            predictions = self.model.predict(features_for_model)
            df['prediction'] = predictions

            # Sadece DDoS olarak işaretlenen (prediction == 1) akışları filtrele
            ddos_flows = df[df['prediction'] == 1]

            if not ddos_flows.empty:
                print(f"\n[!!!] {self.controller.name} DİKKAT: {len(ddos_flows)} ADET ŞÜPHELİ DDOS AKIŞI TESPİT EDİLDİ! [!!!]")
                
                # Aynı IP çifti birden fazla satır (flow) oluşturmuş olabilir.
                # Konsolu spamllememek için eşsiz (unique) Saldırgan-Kurban çiftlerini alalım:
                unique_attackers = ddos_flows[['firstIp', 'secondIp']].drop_duplicates()
                
                for index, row in unique_attackers.iterrows():
                    first_ip = row['firstIp']
                    second_ip = row['secondIp']
                    print(f" -> [TEHDİT] First IP: {first_ip} <|> Second IP: {second_ip}")
                    
                    # --- CANLI BLOKLAMA İÇİN YER TUTUCU ---
                    # İleride P4 switch'e kural yazdırmak için burayı aktif edeceksin:
                    # self.controller.add_drop_rule(first_ip)
            else:
                print(f"[{self.controller.name}] 5 saniyelik pencerede trafik temiz.") # İsteğe bağlı log

            # Memory serbest bırakma (Garbage Collector'a yardım)
            del features_for_model
            del ddos_flows
            del df 
            del datas