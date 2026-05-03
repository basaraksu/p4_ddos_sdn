import sys
import os
import time

# Script bu dosyayı core_controller klasörüne kopyalayacağı için 
# controller.py dosyası ile aynı dizinde çalışacaklar.
from controller import DDoSController

def main():
    print("=====================================================")
    print("  DAĞITIK SDN KONTROLCÜ KÜMESİ BAŞLATILIYOR (SCENARIO 1)")
    print("=====================================================")
    
    # ---------------------------------------------------------
    # BÖLGE 1(C1)
    # Yönetilen Switchler: S1, S2
    # ---------------------------------------------------------
    sanayi_switches = [
        {"name": "s1", "grpc_port": 50051, "device_id": 0},
        {"name": "s2", "grpc_port": 50052, "device_id": 1}
    ]
    
    # ---------------------------------------------------------
    # BÖLGE 2 (C2)
    # Yönetilen Switchler: S3, S4
    # ---------------------------------------------------------
    konut_switches = [
        {"name": "s3", "grpc_port": 50053, "device_id": 2},
        {"name": "s4", "grpc_port": 50054, "device_id": 3}
    ]

    # ---------------------------------------------------------
    # BÖLGE 3 (C3)
    # Yönetilen Switchler: S5
    # ---------------------------------------------------------
    merkez_switches = [
        {"name": "s5", "grpc_port": 50055, "device_id": 4}
    ]

    # 1. Kontrolcü Objelerini (Thread) Yaratıyoruz
    # Her biri kendi bölgelerinin özelliklerini (Feature) ayrı CSV'lere yazacak!
    c1 = DDoSController(
        name="C1", 
        switch_list=sanayi_switches, 
        csv_file_name="features_c1.csv"
    )
    
    c2 = DDoSController(
        name="C2", 
        switch_list=konut_switches, 
        csv_file_name="features_c2.csv"
    )
    
    c3 = DDoSController(
        name="C3", 
        switch_list=merkez_switches, 
        csv_file_name="features_c3.csv"
    )

    # 2. Bütün Kontrolcüleri Paralel Olarak (Thread) Başlatıyoruz
    print("\n--- Kontrolcü Ağacındaki Thread'ler Uyanıyor... ---")
    c1.start()
    time.sleep(1) # Ekrana yazdırırken çıktılar birbirine girmesin diye ufak bekleme
    c2.start()
    time.sleep(1)
    c3.start()

    # 3. Ana Programı Açık Tut (Daemon thread'lerin kapanmaması için)
    print("\n[SİSTEM AKTİF] Tüm kümeler dinlemede. Çıkmak için CTRL+C yapın.\n")
    try:
        while True:
            time.sleep(10) # CPU'yu yormadan bekle
    except KeyboardInterrupt:
        print("\n\n[SİSTEM KAPATILIYOR] Kullanıcı tarafından durduruldu.")
        # Burada gerekirse dosyaları güvenle kapatma işlemleri yapılabilir.
        sys.exit(0)

if __name__ == '__main__':
    main()