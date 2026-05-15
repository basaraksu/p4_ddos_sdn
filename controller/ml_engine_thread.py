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
        self.model = joblib.load('../models/my_model_2.pkl')
        
    def write_to_csv(self, df):
        filename = f'../data/{self.controller.csv_file_name}'
        is_file_new = not os.path.exists(filename)
        df.to_csv(filename, mode='a', header=is_file_new, index=False)
        
    def predict_and_defend(self, df):
        # Modelin eğitilirken görmediği kimlik sütunlarını çıkarıyoruz
        features_for_model = df.drop(columns=['flow_id', 'firstIp', 'switch_name', 'controller_name', 'secondIp', 'firstPort', 'secondPort'])
        
        # Tahminleri yap ve DataFrame'e ekle (0: Normal, 1: DDoS)
        predictions = self.model.predict(features_for_model)
        df['prediction'] = predictions

        # Sadece DDoS olarak işaretlenen (prediction == 1) akışları filtrele
        ddos_flows = df[df['prediction'] == 1]

        if not ddos_flows.empty:
            # Önce saldırganı her satır için belirle
            ddos_flows['malicious_ip'] = ddos_flows.apply(
                lambda r: r['firstIp'] if r['first_count'] > r['second_count'] else r['secondIp'], axis=1
            )
            
            # Şimdi sadece eşsiz saldırganları al
            unique_malicious_ips = ddos_flows['malicious_ip'].unique()
            
            for m_ip in unique_malicious_ips:
                print(f"[{self.controller.name}] DDoS Saldırısı Tespit Edildi! Saldırgan IP: {m_ip}")
                # ---  SAVUNMA MEKANİZMASI  ---
                
                self.controller.ban_queue.put(m_ip)  # Ban kuyruğuna saldırgan IP'yi ekle
                print(f"[{self.controller.name}] {m_ip} Ban Kuyruğuna eklendi!")
        else:
            print(f"[{self.controller.name}] 5 saniyelik pencerede trafik temiz.") # İsteğe bağlı log
        del features_for_model
        del ddos_flows
        
    def run(self):
        print(f"--- {self.controller.name} ML Engine basladi. 5 saniyelik pencerelerle dinleniyor... ---")
        colnames = ['flow_id', 'switch_name', 'controller_name', 'firstIp', 'secondIp', 'firstPort', 'secondPort', 
                    'first_count', 'second_count', 'first_rate', 'second_rate', 'Dur', 'Bytes', 'proto_number']
                
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
            
           # --- SİMETRİK KÜMÜLATİF HESAPLAMALAR (IP BAZLI) ---
            # 1. Tüm IP'lerin (hem first hem second) toplam benzersiz bağlantılarını hesaplayalım
            all_conns = pd.concat([
                df[['firstIp', 'secondIp']].rename(columns={'firstIp': 'IP', 'secondIp': 'Peer'}),
                df[['secondIp', 'firstIp']].rename(columns={'secondIp': 'IP', 'firstIp': 'Peer'})
            ])

            # Her IP için kaç tane benzersiz 'Peer' (eş) olduğunu bulalım
            conn_counts = all_conns.groupby('IP')['Peer'].nunique().to_dict()

            # Gerçek değerleri ana tablomuza geri yazalım
            df['N_Conn_P_FirstIP'] = df['firstIp'].map(conn_counts).fillna(0)
            df['N_Conn_P_SecondIP'] = df['secondIp'].map(conn_counts).fillna(0)
            
            # Ortalama Paket Boyutu (1e-6 ile sıfıra bölünme hatası engellenmiş, harika!)
            df['Avg_Packet_Size'] = df['Bytes'] / (df['first_count'] + df['second_count'] + 1e-6)

            # --- YÖNLÜ KÜMÜLATİF HESAPLAMALAR (PORT BAZLI ZIRH) ---
            # Her bir Kaynak IP'nin (firstIp) kaç farklı Hedef Porta saldırdığını bul
            port_counts_first = df.groupby('firstIp')['secondPort'].nunique().to_dict()
            # Her bir Hedef IP'nin (secondIp) kaç farklı Kaynak Porttan istek aldığını bul
            port_counts_second = df.groupby('secondIp')['firstPort'].nunique().to_dict()

            # Port değerlerini ana tabloya yazalım
            df['N_PortP_FirstIp'] = df['firstIp'].map(port_counts_first).fillna(0)
            df['N_PortP_SecondIp'] = df['secondIp'].map(port_counts_second).fillna(0)
            
            # CSV'ye yazma
            #self.write_to_csv(df)
            
            #print(f"--- [ML ENGINE] {len(df)} adet akis islendi ve CSV'ye yazildi. ---")
            
            # --- ML TAHMİNİ VE SAVUNMA TETİKLEME ---
            self.predict_and_defend(df)

            # Memory serbest bırakma (Garbage Collector'a yardım)
            
            del df 
            del datas