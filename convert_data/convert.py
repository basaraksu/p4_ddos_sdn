import pandas as pd
import os

# 1. Verileri Yükle
df1 = pd.read_csv('features_c1.csv')
df2 = pd.read_csv('features_c2.csv')
df3 = pd.read_csv('features_c3.csv')

# Dataframeleri birleştir
df = pd.concat([df1, df2, df3], ignore_index=True)

# 2. IP Listeleri
whitelist_ips = [
    # S1 Bölgesi (10.0.1.x)
    "10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.14", "10.0.1.18",
    # S2 Bölgesi (10.0.2.x)
    "10.0.2.4",  "10.0.2.15", "10.0.2.19",
    # S3 Bölgesi (10.0.3.x)
    "10.0.3.6", "10.0.3.7", "10.0.3.16",
    # S4 Bölgesi (10.0.4.x)
    "10.0.4.8", "10.0.4.9",  "10.0.4.17",
    # S5 Merkez Bölgesi (10.0.5.x - Kurbanlar ve Sunucular)
    "10.0.5.11", "10.0.5.12", "10.0.5.13", "10.0.5.20"
]

blocklist_ips = [
    # S2 Bölgesi (10.0.2.x) - Saldırgan 1 (h5)
    "10.0.2.5",
    # S4 Bölgesi (10.0.4.x) - Saldırgan 2 (h10)
    "10.0.4.10"    
]

# Random (Spoofed) IP olup olmadığını anlamak için bilinen IP'leri birleştiriyoruz
known_ips = set(whitelist_ips + blocklist_ips)

# 3. Labellama Fonksiyonu
def label_traffic(row):
    first_ip = row['firstIp']
    second_ip = row['secondIp']
    fwd_count = row['fwd_count']
    bwd_count = row['bwd_count']
    
    # Kural 1: Eğer firstIp blocklist'te ise (Non-Spoofed saldırgan başlatıyor) -> Saldırı (1)
    if first_ip in blocklist_ips:
        return 1
        
    # IP'lerin random (spoofed) olup olmadığını kontrol et
    is_first_random = first_ip not in known_ips
    is_second_random = second_ip not in known_ips
    
    # Kural 2: Eğer IP'lerden en az biri random (spoofed) ise
    if is_first_random or is_second_random:
        # firstIp random iken ileri yönde paket varsa -> Saldırı (1)
        if is_first_random and fwd_count > 0:
            return 1
        # secondIp random iken geri yönde paket varsa -> Saldırı (1)
        elif is_second_random and bwd_count > 0:
            return 1
        # Diğer durumlar (örneğin kurbanın random IP'ye verdiği yanıt trafikleri) -> Normal (0)
        else:
            return 0
            
    # Kural 3: Kalan tüm durumlar (iki IP de Whitelist'te ise vb.) -> Normal Trafik (0)
    return 0

# 4. Fonksiyonu DataFrame'e Uygula ve 'label' Sütununu Oluştur
df['label'] = df.apply(label_traffic, axis=1)

# Adım 5.1: Aynı trafiğin farklı switch'ler (s1 ve s5) tarafından yazılmasını engellemek için,
# switch_name, controller_name ve flow_id DIŞINDAKİ tüm sütunlara bakarak kopya arayacağız.
# (Böylece farklı IP'lerin tesadüfen aynı paket sayısına sahip olduğu durumlar silinmeyecek!)
subset_cols = [col for col in df.columns if col not in ['switch_name', 'controller_name', 'flow_id']]

initial_row_count = len(df)
# Belirlediğimiz sütunları baz alarak aynı olanları sil (sadece ilkini tut)
df_cleaned = df.drop_duplicates(subset=subset_cols, keep='first').copy()
final_row_count = len(df_cleaned)

print(f"Toplam Satır: {initial_row_count}")
print(f"Farklı Switch'lerin Yazdığı Aynı Trafik (Kopya) Sayısı: {initial_row_count - final_row_count}")
print(f"Ağdaki Gerçek Eşsiz Akış Sayısı: {final_row_count}")

df_cleaned.to_csv('data.csv', index=False)