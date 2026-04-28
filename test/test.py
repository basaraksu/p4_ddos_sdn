import pandas as pd
import joblib
from sklearn.metrics import classification_report, confusion_matrix
import os

def validate_model():
    # 1. Dosya Kontrolleri
    if not os.path.exists("features.csv") or not os.path.exists("ddos_rf_model.pkl"):
        print("Hata: csv veya pkl dosyası bulunamadı!")
        return

    # 2. Veriyi ve Modeli Yükle
    df = pd.read_csv("features.csv")
    model = joblib.load('ddos_rf_model.pkl')
    
    # 3. Gerçek Etiketleri Hazırla (h1: 10.0.1.1 saldırgan olduğunu biliyoruz)
    y_true = df['firstIp'].apply(lambda x: 1 if x == '10.0.1.1' else 0)

    # 4. Modele Girecek Sütunları SIRALI Şekilde Ayır
    # ÖNEMLİ: Senin modelin tam olarak bu sırayı bekliyor!
    target_columns = ['N_IN_Conn_P_DstIP', 'TnP_PDstIP', 'Srate', 'Drate', 'Dur', 'Bytes', 'proto_number']
    X_test = df[target_columns]

    print(f"--- Toplam {len(df)} satır veri işleniyor... ---")

    # 5. Tahmin Yap
    try:
        y_pred = model.predict(X_test)
        
        # 6. Sonuçları Tabloya Ekle
        df['tahmin_etiketi'] = y_pred
        df['asil_etiket'] = y_true.values

        # 7. Raporlama
        print("\n=== KARMAŞIKLIK MATRİSİ ===")
        print(confusion_matrix(y_true, y_pred))

        print("\n=== SINIFLANDIRMA RAPORU ===")
        print(classification_report(y_true, y_pred))

        # 8. Başarı Analizi
        basarili = (df['tahmin_etiketi'] == df['asil_etiket']).sum()
        basari_orani = (basarili / len(df)) * 100
        print(f"\nSonuç: {len(df)} paketten {basarili} tanesi doğru bilindi.")
        print(f"Genel Doğruluk Oranı: %{basari_orani:.2f}")

        # 9. Yanlışları Göster (Eğer varsa)
        hatalar = df[df['tahmin_etiketi'] != df['asil_etiket']]
        if not hatalar.empty:
            print("\n!!! HATALI TAHMİNLER !!!")
            print(hatalar[['firstIp', 'Srate', 'TnP_PDstIP', 'asil_etiket', 'tahmin_etiketi']])
            
        # 10. Başarılı Göster
        dogru_tahminler = df[df['tahmin_etiketi'] == df['asil_etiket']]
        if not dogru_tahminler.empty:
            print("\n--- DOĞRU TAHMİNLER ---")
            print(dogru_tahminler[['firstIp', 'Srate', 'TnP_PDstIP', 'asil_etiket', 'tahmin_etiketi']])

    except Exception as e:
        print(f"Tahmin sırasında hata oluştu: {e}")

if __name__ == "__main__":
    validate_model()