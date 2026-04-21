import numpy as np
import joblib  # veya modelini nasıl yüklediysen (pickle vb.)

# 1. Sözlüğü yükle
loaded_data = joblib.load('ddos_xgboost_model.pkl')

# 2. Modeli sözlüğün içinden çek (Hata buradaydı)
model = loaded_data['model']


#2. Elindeki Canlı Verileri Hazırla
#Format: [rate_ratio, byte_ratio, srate, drate, TnP_PDstIP, N_IN_Conn, proto, TnP_Per_Dport]
#(TnP_Per_Dport senin verilerinde yoksa veya 0 ise o sütunu da loglayıp eklemelisin)

# Senin Paylaştığın Ping Verisi
ping_data = np.array([[
    1.0,                # rate_ratio
    1.0196032672112019,               # byte_ratio
    1.0192307692307692,                # packet_ratio    
    2.4,  # srate (log)
    2.41, # drate (log)
    2.61,  # TnP_PDstIP (log)
    2.41, # N_IN_Conn (log)
    1,                  # proto_number (ICMP)
]])

# Senin Paylaştığın Hping3 (Flood) Verisi
hping_data = np.array([[
    1000,               # rate_ratio (clip edilmiş)
    1000,               # byte_ratio (clip edilmiş)
    1000,                  # packet_ratio
    7.2520539518528135, # srate (log)
    0.0,                # drate (log)
    7.255591274253665,  # TnP_PDstIP (log)
    1.0986122886681096, # N_IN_Conn (log)
    6,                  # proto_number (TCP)
]])

# 3. Tahminleri Yürüt
print("--- DDoS Model Testi ---")

# Ping Testi
ping_pred = model.predict(ping_data)
ping_prob = model.predict_proba(ping_data)[:, 1] # Olasılık görmek istersen
print(f"Ping Trafiği Sonucu: {ping_pred[0]} (Beklenen: 0)")
print(f"Ping Trafiği Olasılığı: {ping_prob[0]:.4f}")

# Hping Testi
hping_pred = model.predict(hping_data)
hping_prob = model.predict_proba(hping_data)[:, 1]
print(f"Hping3 Flood Sonucu: {hping_pred[0]} (Beklenen: 1)")
print(f"Hping3 Flood Olasılığı: {hping_prob[0]:.4f}")

if hping_pred[0] == 1:
    print("\n[BAŞARILI] Model saldırıyı doğru ayırt etti!")
