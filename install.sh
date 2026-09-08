#!/bin/bash
# PHL5 - Siber Güvenlik & OSINT Aracı Kurulumu

echo "[+] PHL5 kurulumu başlatılıyor..."

# Gerekli paketleri yükle
echo "[+] Sistem paketleri güncelleniyor..."
sudo apt update && sudo apt upgrade -y

# Python ve pip kontrolü
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 bulunamadı, kuruluyor..."
    sudo apt install python3 python3-pip -y
fi

# Gerekli Python kütüphanelerini kur
echo "[+] Python kütüphaneleri kuruluyor..."
pip3 install -r requirements.txt

# Çalıştırma izni ver
chmod +x phl5.py

echo "[+] PHL5 başarıyla kuruldu!"
echo "[+] Çalıştırmak için: python3 phl5.py"
