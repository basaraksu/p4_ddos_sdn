import joblib
import pandas as pd
import numpy as np

def final_diagnostic():
    # 1. Modeli Yükle
    model = joblib.load('insdn_xgb_top10.pkl')
    
    # 2. Modelin GERÇEK sıralamasını al
    # XGBClassifier içinde bu genellikle 'feature_names_in_' altındadır
    try:
        expected_features = model.feature_names_in_
        print(f"Modelin Beklediği Sıralama: {list(expected_features)}")
    except AttributeError:
        # Eğer yukarıdaki çalışmazsa booster'dan çekelim
        expected_features = model.get_booster().feature_names
        print(f"Booster Sıralaması: {expected_features}")

    # 3. TEST: Dehşet Verici Bir Saldırı (Her şey uç noktada)
    # Veriyi bir sözlük (dict) olarak kuralım ki sütun hatası olmasın
    extreme_data = {
        'Bwd Pkts/s': 999999.0,
        'Bwd Header Len': 999999.0,
        'Flow IAT Max': 0.0001,
        'Flow IAT Mean': 0.0001,
        'Tot Fwd Pkts': 999999.0,
        'Bwd IAT Tot': 0.0001,
        'Flow Pkts/s': 999999.0,
        'Fwd Header Len': 999999.0,
        'Flow Duration': 0.1,
        'Fwd IAT Min': 0.00001
    }

    # DataFrame oluştururken SÜTUN SIRASINI modelin beklediğiyle eşitleyelim
    df = pd.DataFrame([extreme_data])[list(expected_features)]

    # 4. Tahmin
    proba = model.predict_proba(df)[0]
    
    print("\n" + "="*40)
    print(f"Normal Olasılığı: %{proba[0]*100:.4f}")
    print(f"Saldırı Olasılığı: %{proba[1]*100:.4f}")
    print("="*40)

if __name__ == "__main__":
    final_diagnostic()