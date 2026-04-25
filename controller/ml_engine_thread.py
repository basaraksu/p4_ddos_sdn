from scapy.all import *
import threading
import time
import queue
import joblib
import warnings
warnings.filterwarnings("ignore")  # Özellikle ML modelinden gelen uyarıları gizle

class MLEngineThread(threading.Thread):
    def __init__(self, switch, controller, daemon=True):
        super().__init__(daemon=daemon)
        self.switch = switch
        self.controller = controller
        self.model = joblib.load('../models/ddos_rf_model.pkl')  # ML modelini yükle
        self.scaler = joblib.load('../models/robust_scaler.pkl')  # Özellik ölçekleyicisini yükle
        
        
    def run(self):
        print(f"--- {self.switch.name} ML Engine verileri dinleniyor... ---")
        while True:
            try:
                # Feature mesajını al
                feature = self.controller.q_feature.get()

                if not feature:
                    continue
                
                flow_id = feature['flow_id']
                features_df = feature['features']

                # ML modeline gönder ve tahmin al
                
                # Özellikleri ölçeklendir
                scaled_features = self.scaler.transform(features_df)
                prediction = self.model.predict(scaled_features)[0]
                print(f"--- Tahmin alindi: Flow ID {flow_id}, Prediction: {prediction}")
                #print(f"    Features:\n{features_df.to_string()}")
                print(f"********************************************************************")
                
                      
            except Exception as e:
                print(f"Model Hatası: {e}")
                time.sleep(1) # Hata durumunda döngüyü yavaşlat
    ...