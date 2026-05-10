import pandas as pd
import os

# 1. Verileri Yükle
df1 = pd.read_csv('features_c1.csv')
df2 = pd.read_csv('features_c2.csv')
df3 = pd.read_csv('features_c3.csv')
df4 = pd.read_csv('features_c4.csv')
df5 = pd.read_csv('features_c5.csv')

# Dataframeleri birleştir
df = pd.concat([df1, df2, df3, df4, df5], ignore_index=True)

# 2. IP Listeleri
whitelist_ips = [
    # Domain 1 (Sanayi)
    '10.0.1.1', '10.0.1.2', '10.0.1.3', '10.0.1.4', '10.0.1.5',
    '10.0.2.1', '10.0.2.2', '10.0.2.3', '10.0.2.4', 
    # Domain 2 (Konut)
    '10.0.3.1', '10.0.3.2', '10.0.3.3', '10.0.3.4', '10.0.3.5',
    '10.0.4.1', '10.0.4.2', '10.0.4.3', '10.0.4.4', 
    # Domain 3 (Hastane/Kamu)
    '10.0.5.1', '10.0.5.2', '10.0.5.3', '10.0.5.4', '10.0.5.5',
    '10.0.6.1', '10.0.6.2', '10.0.6.3', '10.0.6.4', 
    # Domain 4 (Finans)
    '10.0.7.1', '10.0.7.2', '10.0.7.3', '10.0.7.4', '10.0.7.5',
    '10.0.8.1', '10.0.8.2', '10.0.8.3', '10.0.8.4', 
    # Domain 5 (Veri Merkezi - Sunucular ve Gürültü)
    '10.0.9.1', '10.0.9.2', '10.0.9.3', '10.0.9.4', '10.0.9.5',
    '10.0.10.1', '10.0.10.2', '10.0.10.3', '10.0.10.4'
]
blocklist_ips = ['10.0.2.5', '10.0.4.5', '10.0.6.5', '10.0.8.5', '10.0.10.5']

# Random (Spoofed) IP olup olmadığını anlamak için bilinen IP'leri birleştiriyoruz
known_ips = set(whitelist_ips + blocklist_ips)

# 3. Labellama Fonksiyonu
def label_traffic(row):
    first_ip = row['firstIp']
    second_ip = row['secondIp']
    first_count = row['first_count']
    second_count = row['second_count']

    # Kural 1: Eğer firstIp blocklist'te ise (Non-Spoofed saldırgan başlatıyor) -> Saldırı (1)
    if first_ip in blocklist_ips or second_ip in blocklist_ips:
        if first_ip in blocklist_ips and first_count > second_count:
            return 1
        elif second_ip in blocklist_ips and second_count > first_count:
            return 1
        else:
            return 0

    # IP'lerin random (spoofed) olup olmadığını kontrol et
    is_first_random = first_ip not in known_ips
    is_second_random = second_ip not in known_ips
    
    # Kural 2: Eğer IP'lerden en az biri random (spoofed) ise
    if is_first_random or is_second_random:
        # firstIp random iken ileri yönde paket varsa -> Saldırı (1)
        if is_first_random and first_count > second_count:
            return 1
        # secondIp random iken geri yönde paket varsa -> Saldırı (1)
        elif is_second_random and second_count > first_count:
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

df_cleaned.to_csv('data2_1.csv', index=False)