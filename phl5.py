#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# PHL5 - Siber Güvenlik & OSINT Aracı
# Sadece EĞİTİM ve YASAL testler için kullanınız.

import os
import sys
import json
import socket
import requests
import whois
import dns.resolver
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
import subprocess
import psutil
import platform
from datetime import datetime

# ─── RENKLİ ÇIKTI ──────────────────────────────────────
class Color:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# ─── BANNER ────────────────────────────────────────────
def banner():
    print(f"""{Color.CYAN}
    ╔══════════════════════════════════════════════╗
    ║   ██████╗ ██╗  ██╗██╗      ██████╗         ║
    ║   ██╔══██╗██║  ██║██║     ██╔═══╝         ║
    ║   ██████╔╝███████║██║     ██████╗         ║
    ║   ██╔═══╝ ██╔══██║██║     ╚════██╗        ║
    ║   ██║     ██║  ██║███████╗██████║        ║
    ║   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═════╝        ║
    ║              SİBER GÜVENLİK & OSINT          ║
    ╚══════════════════════════════════════════════╝
    {Color.RESET}""")
    print(f"{Color.YELLOW}[!] Yalnızca EĞİTİM ve YASAL testler için kullanınız.")
    print(f"{Color.YELLOW}[!] İzinsiz kullanım SUÇTUR. TCK 243-245, KVKK{Color.RESET}\n")

# ─── YABANCI IP ALGILAMA ─────────────────────────────

def foreign_ip_check(ip):
    """IP'nin yabancı olup olmadığını kontrol eder"""
    print(f"\n{Color.BLUE}[+] Yabancı IP Kontrolü: {ip}{Color.RESET}")
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = response.json()
        country = data.get('country', '?')
        city = data.get('city', '?')
        region = data.get('region', '?')
        org = data.get('org', '?')
        
        print(f"{Color.GREEN}📍 Konum: {city}, {region}, {country}{Color.RESET}")
        print(f"{Color.GREEN}🏢 ISP: {org}{Color.RESET}")
        
        if country == 'TR':
            print(f"{Color.GREEN}✅ Bu IP Türkiye'ye ait. Güvenli.{Color.RESET}")
        else:
            print(f"{Color.RED}⚠️ BU IP YABANCI! ({country}){Color.RESET}")
            print(f"{Color.RED}   Dikkatli olun!{Color.RESET}")
    except Exception as e:
        print(f"{Color.RED}❌ IP sorgulanamadı: {e}{Color.RESET}")

# ─── BİLGİSAYAR GÜVENLİK TESTİ ───────────────────────

def security_test():
    """Windows güvenlik testi (port, işlem, firewall, antivirüs)"""
    print(f"\n{Color.BLUE}[+] BİLGİSAYAR GÜVENLİK TESTİ BAŞLATILIYOR...{Color.RESET}")
    
    # 1. İşletim sistemi bilgisi
    print(f"\n{Color.YELLOW}[1] İşletim Sistemi:{Color.RESET}")
    print(f"   {platform.system()} {platform.release()} ({platform.version()})")
    
    # 2. Açık portlar (yerel)
    print(f"\n{Color.YELLOW}[2] Açık Portlar (yerel):{Color.RESET}")
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443]
    open_ports = []
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                open_ports.append(port)
                print(f"   {Color.GREEN}✅ Port {port} AÇIK{Color.RESET}")
            sock.close()
        except:
            pass
    if not open_ports:
        print(f"   {Color.GREEN}✅ Açık port bulunamadı.{Color.RESET}")
    
    # 3. Çalışan işlemler (ilk 10)
    print(f"\n{Color.YELLOW}[3] Çalışan İşlemler (ilk 10):{Color.RESET}")
    try:
        processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']))[:10]
        for p in processes:
            try:
                mem = p.info['memory_info'].rss / (1024 * 1024) if p.info['memory_info'] else 0
                print(f"   {p.info['pid']}: {p.info['name']} (CPU: {p.info['cpu_percent']}%, RAM: {mem:.1f} MB)")
            except:
                pass
    except:
        print(f"   {Color.RED}❌ İşlem listesi alınamadı.{Color.RESET}")
    
    # 4. Windows Güvenlik Duvarı Durumu
    print(f"\n{Color.YELLOW}[4] Windows Güvenlik Duvarı:{Color.RESET}")
    try:
        result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True)
        if 'State                                 ON' in result.stdout:
            print(f"   {Color.GREEN}✅ Güvenlik duvarı AÇIK{Color.RESET}")
        else:
            print(f"   {Color.RED}⚠️ Güvenlik duvarı KAPALI veya bilinmiyor{Color.RESET}")
    except:
        print(f"   {Color.RED}❌ Güvenlik duvarı durumu alınamadı.{Color.RESET}")
    
    # 5. Windows Defender Durumu
    print(f"\n{Color.YELLOW}[5] Windows Defender:{Color.RESET}")
    try:
        result = subprocess.run(['powershell', '-Command', 'Get-MpComputerStatus'], capture_output=True, text=True)
        if 'AntivirusEnabled              : True' in result.stdout:
            print(f"   {Color.GREEN}✅ Antivirüs AKTİF{Color.RESET}")
        else:
            print(f"   {Color.RED}⚠️ Antivirüs PASİF veya bilinmiyor{Color.RESET}")
    except:
        print(f"   {Color.RED}❌ Defender durumu alınamadı.{Color.RESET}")
    
    # 6. Zafiyet Kontrolü (RDP, SMBv1)
    print(f"\n{Color.YELLOW}[6] Yaygın Zafiyet Kontrolü:{Color.RESET}")
    # RDP (3389)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        if sock.connect_ex(('127.0.0.1', 3389)) == 0:
            print(f"   {Color.RED}⚠️ RDP (3389) AÇIK - Uzaktan masaüstü riski!{Color.RESET}")
        else:
            print(f"   {Color.GREEN}✅ RDP (3389) KAPALI{Color.RESET}")
        sock.close()
    except:
        pass
    
    # SMBv1 (445)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        if sock.connect_ex(('127.0.0.1', 445)) == 0:
            print(f"   {Color.YELLOW}⚠️ SMB (445) AÇIK - Dosya paylaşımı riski!{Color.RESET}")
        else:
            print(f"   {Color.GREEN}✅ SMB (445) KAPALI{Color.RESET}")
        sock.close()
    except:
        pass
    
    print(f"\n{Color.GREEN}[+] Güvenlik testi tamamlandı.{Color.RESET}")

# ─── OSINT MODÜLLERİ (önceki) ────────────────────────

def osint_email(email):
    """E-posta sorgulama"""
    print(f"\n{Color.BLUE}[+] E-posta OSINT: {email}{Color.RESET}")
    if '@' not in email or '.' not in email.split('@')[1]:
        print(f"{Color.RED}❌ Geçersiz e-posta formatı.{Color.RESET}")
        return
    try:
        domain = email.split('@')[1]
        mx_records = dns.resolver.resolve(domain, 'MX')
        print(f"{Color.GREEN}✅ MX Kaydı bulundu:{Color.RESET}")
        for mx in mx_records:
            print(f"   {mx.exchange}")
    except:
        print(f"{Color.RED}❌ MX kaydı bulunamadı.{Color.RESET}")
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        response = requests.get(url, headers={"hibp-api-key": ""})
        if response.status_code == 200:
            data = response.json()
            print(f"{Color.RED}⚠️ BU E-POSTA VERİ SIZINTISINDA BULUNDU!{Color.RESET}")
            for breach in data:
                print(f"   - {breach['Name']} ({breach['BreachDate']})")
        elif response.status_code == 404:
            print(f"{Color.GREEN}✅ Bu e-posta bilinen bir sızıntıda yok.{Color.RESET}")
        else:
            print(f"{Color.YELLOW}⚠️ HIBP sorgusu başarısız (kod: {response.status_code}){Color.RESET}")
    except:
        print(f"{Color.RED}❌ HIBP sorgusu yapılamadı.{Color.RESET}")

def osint_username(username):
    """Kullanıcı adı OSINT"""
    print(f"\n{Color.BLUE}[+] Kullanıcı Adı OSINT: {username}{Color.RESET}")
    sites = {
        "GitHub": f"https://github.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Reddit": f"https://reddit.com/user/{username}",
        "YouTube": f"https://youtube.com/@{username}",
        "TikTok": f"https://tiktok.com/@{username}",
        "Pinterest": f"https://pinterest.com/{username}",
        "Spotify": f"https://open.spotify.com/user/{username}",
    }
    found = 0
    for name, url in sites.items():
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                print(f"{Color.GREEN}✅ {name}: {url}{Color.RESET}")
                found += 1
            else:
                print(f"{Color.RED}❌ {name}: bulunamadı{Color.RESET}")
        except:
            print(f"{Color.YELLOW}⚠️ {name}: bağlantı hatası{Color.RESET}")
    print(f"{Color.CYAN}[+] Toplam {found} platformda bulundu.{Color.RESET}")

def osint_ip(ip):
    """IP sorgulama"""
    print(f"\n{Color.BLUE}[+] IP OSINT: {ip}{Color.RESET}")
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = response.json()
        if 'bogon' in data and data['bogon']:
            print(f"{Color.YELLOW}⚠️ Bu IP özel/yerel ağa ait.{Color.RESET}")
        else:
            print(f"{Color.GREEN}📍 Konum: {data.get('city', '?')}, {data.get('region', '?')}, {data.get('country', '?')}{Color.RESET}")
            print(f"{Color.GREEN}🏢 ISP: {data.get('org', '?')}{Color.RESET}")
            print(f"{Color.GREEN}🌐 Koordinat: {data.get('loc', '?')}{Color.RESET}")
    except:
        print(f"{Color.RED}❌ IP sorgulanamadı.{Color.RESET}")

def osint_domain(domain):
    """Domain WHOIS"""
    print(f"\n{Color.BLUE}[+] Domain OSINT: {domain}{Color.RESET}")
    try:
        w = whois.whois(domain)
        print(f"{Color.GREEN}📅 Kayıt Tarihi: {w.creation_date}{Color.RESET}")
        print(f"{Color.GREEN}📅 Bitiş Tarihi: {w.expiration_date}{Color.RESET}")
        print(f"{Color.GREEN}👤 Kayıt Sahibi: {w.name}{Color.RESET}")
        print(f"{Color.GREEN}📧 E-posta: {w.email}{Color.RESET}")
        print(f"{Color.GREEN}🏢 Kuruluş: {w.org}{Color.RESET}")
    except:
        print(f"{Color.RED}❌ WHOIS sorgulanamadı.{Color.RESET}")

def osint_phone(phone):
    """Telefon OSINT"""
    print(f"\n{Color.BLUE}[+] Telefon OSINT: {phone}{Color.RESET}")
    try:
        num = phonenumbers.parse(phone, None)
        if phonenumbers.is_valid_number(num):
            print(f"{Color.GREEN}✅ Geçerli numara{Color.RESET}")
            print(f"{Color.GREEN}🌍 Ülke: {geocoder.description_for_number(num, 'tr')}{Color.RESET}")
            print(f"{Color.GREEN}📡 Operatör: {carrier.name_for_number(num, 'en')}{Color.RESET}")
            print(f"{Color.GREEN}🕒 Zaman Dilimi: {timezone.time_zones_for_number(num)}{Color.RESET}")
        else:
            print(f"{Color.RED}❌ Geçersiz numara{Color.RESET}")
    except:
        print(f"{Color.RED}❌ Numara parse edilemedi.{Color.RESET}")

# ─── PORT TARAMA (önceki) ─────────────────────────────

def port_scan(target, ports=None):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443]
    print(f"\n{Color.BLUE}[+] Port Tarama: {target}{Color.RESET}")
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                print(f"{Color.GREEN}✅ Port {port} AÇIK{Color.RESET}")
            sock.close()
        except:
            pass
    if not open_ports:
        print(f"{Color.RED}❌ Açık port bulunamadı.{Color.RESET}")

# ─── ŞİFRE GÜCÜ (önceki) ─────────────────────────────

def password_strength(password):
    print(f"\n{Color.BLUE}[+] Şifre Gücü Testi{Color.RESET}")
    score = 0
    if len(password) >= 8:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in "!@#$%^&*()_+-=[]{};:'\",.<>?/" for c in password):
        score += 1
    if score <= 2:
        print(f"{Color.RED}❌ Zayıf şifre (puan: {score}/5){Color.RESET}")
    elif score <= 3:
        print(f"{Color.YELLOW}⚠️ Orta şifre (puan: {score}/5){Color.RESET}")
    else:
        print(f"{Color.GREEN}✅ Güçlü şifre (puan: {score}/5){Color.RESET}")

# ─── ANA MENÜ ──────────────────────────────────────────

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()
    while True:
        print(f"{Color.CYAN}═══════════════════════════════════════════════{Color.RESET}")
        print(f"{Color.YELLOW} 1. E-posta OSINT")
        print(f" 2. Kullanıcı Adı OSINT")
        print(f" 3. IP OSINT")
        print(f" 4. Domain WHOIS")
        print(f" 5. Telefon OSINT")
        print(f" 6. Port Tarama")
        print(f" 7. Şifre Gücü Testi")
        print(f" 8. Yabancı IP Algılama")
        print(f" 9. Bilgisayar Güvenlik Testi")
        print(f" 0. Çıkış")
        print(f"{Color.CYAN}═══════════════════════════════════════════════{Color.RESET}")
        
        choice = input(f"{Color.GREEN}PHL5> {Color.RESET}").strip()
        
        if choice == '0':
            print(f"{Color.RED}Çıkış yapılıyor...{Color.RESET}")
            break
        elif choice == '1':
            email = input("E-posta: ")
            osint_email(email)
        elif choice == '2':
            username = input("Kullanıcı adı: ")
            osint_username(username)
        elif choice == '3':
            ip = input("IP adresi: ")
            osint_ip(ip)
        elif choice == '4':
            domain = input("Domain: ")
            osint_domain(domain)
        elif choice == '5':
            phone = input("Telefon (örn: +905551234567): ")
            osint_phone(phone)
        elif choice == '6':
            target = input("Hedef IP/Domain: ")
            port_scan(target)
        elif choice == '7':
            pwd = input("Şifre: ")
            password_strength(pwd)
        elif choice == '8':
            ip = input("IP adresi: ")
            foreign_ip_check(ip)
        elif choice == '9':
            security_test()
        else:
            print(f"{Color.RED}Geçersiz seçenek.{Color.RESET}")

if __name__ == "__main__":
    main()
