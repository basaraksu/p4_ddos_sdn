#!/bin/bash

# Eğer senaryo adı girilmediyse uyar
if [ -z "$1" ]; then
    echo "HATA: Lutfen bir senaryo klasoru belirtin!"
    echo "Kullanim: ./setup_scenario.sh <senaryo_klasoru_adi>"
    echo "Ornek: ./setup_scenario.sh scenario_1_single_switch"
    exit 1
fi

SCENARIO_DIR="topologies/$1"

# Klasörün var olup olmadığını kontrol et
if [ ! -d "$SCENARIO_DIR" ]; then
    echo "HATA: '$SCENARIO_DIR' adinda bir klasor bulunamadi!"
    exit 1
fi

echo "=== [$1] Senaryosu Kuruluyor ==="

# 1. Eski runtime, topoloji ve Makefile dosyalarını temizle
echo "-> Eski konfigürasyon dosyalari temizleniyor..."
rm -f s*-runtime.json
rm -f topology.json

# 2. Seçilen senaryonun JSON ve Makefile dosyalarını root dizinine kopyala
echo "-> Yeni topology ve runtime JSON'lari root dizinine kopyalaniyor..."
cp $SCENARIO_DIR/*.json ./

# 3. Main dosyasını Controller klasörüne kopyala
echo "-> Senaryo main dosyasi Controller altina yerlestiriliyor..."
cp $SCENARIO_DIR/main.py ./controller/main.py

echo "======================================================"
echo " BASARILI! Sistem [$1] icin hazir."
echo " Mininet'i baslatmak icin: make run"
echo " Kontrolcuyu baslatmak icin: cd controller && python3 main.py"
echo "======================================================"