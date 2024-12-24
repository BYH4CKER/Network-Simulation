import ipaddress
import nmap
import time
import sys

# Banner
def display_banner():
    print("""
    ██████╗  ██████╗ ████████╗ ██████╗ ██████╗ ██████╗ 
    ██╔══██╗██╔═══██╗╚══██╔══╝██╔═══██╗██╔══██╗██╔══██╗
    ██████╔╝██║   ██║   ██║   ██║   ██║██║  ██║██████╔╝
    ██╔═══╝ ██║   ██║   ██║   ██║   ██║██║  ██║██╔═══╝ 
    ██║     ╚██████╔╝   ██║   ╚██████╔╝██████╔╝██║     
    ╚═╝      ╚═════╝    ╚═╝    ╚═════╝ ╚═════╝ ╚═╝     
          🔍 PORT TARAYICI ARACI 🔍
           Yazar: Yiğit

    """)

nm = nmap.PortScanner()

# Display the banner
display_banner()

while True:
    print("""\nNe yapmak istersiniz?\n
                    1. Bir cihaz hakkında detaylı bilgi al
                    2. Ağdaki açık portları tara
                    3. Uygulamayı kapat""")
    try:
        user_input = input("\nSeçiminizi girin: ")

        if user_input == '1':
            ip = input("\nLütfen bir IP adresi girin: ")
            try:
                ipaddress.ip_address(ip)
            except ValueError as e:
                print(f"Hatalı IP adresi: {e}")
                continue

            print("\nTaramaya başlıyor... Lütfen bekleyin.")
            sc1 = nm.scan(hosts=ip, ports='1-1024', arguments='-v -sS -sV -O -A')

            if ip not in sc1['scan']:
                print("Hedef IP adresinden yanıt alınamadı.")
                continue

            print(f"\n=================== HOST {ip} ====================\n")
            print("GENEL BİLGİLER\n")

            # MAC adresi
            mac_address = sc1['scan'][ip]['addresses'].get('mac', "Bilinmiyor")
            print(f"*MAC Adresi: {mac_address}\n")

            # İşletim sistemi
            os_version = sc1['scan'][ip].get('osmatch', [{"name": "Bilinmiyor"}])[0]['name']
            print(f"*İşletim Sistemi: {os_version}\n")

            # Cihaz çalışma süresi
            host_uptime = sc1['scan'][ip].get('uptime', {}).get('lastboot', "Bilinmiyor")
            print(f"*Çalışma Süresi: {host_uptime}\n")

            print("\nPORT DURUMLARI\n")
            for port, details in sc1['scan'][ip].get('tcp', {}).items():
                print(f"-> {port} | {details['name']} | {details['state']}")

            print("\nDİĞER BİLGİLER\n")
            print(f"-> NMAP komutu: {sc1['nmap']['command_line']}")
            nmap_version = ".".join(map(str, nm.nmap_version()[:2]))
            print(f"-> NMAP Sürümü: {nmap_version}")
            print(f"-> Geçen Süre: {sc1['nmap']['scanstats']['elapsed']}s")
            print(f"-> Tarama Zamanı: {sc1['nmap']['scanstats']['timestr']}\n")
            continue

        elif user_input == '2':
            print("\nTaramaya başlıyor... Lütfen bekleyin.")
            sc2 = nm.scan(ports='1-1024', arguments='-sS -iL ip_listesi.txt')

            for device in sc2['scan']:
                print(f"\n{device} cihazında açık portlar: ")
                for port, details in sc2['scan'][device]['tcp'].items():
                    if details['state'] == 'open':
                        print(f"--> {port} | {details['name']}")
            continue

        elif user_input == '3':
            print("Programdan çıkılıyor...")
            time.sleep(1)
            break

        else:
            print("Geçersiz giriş, tekrar deneyin.")
            continue
    except KeyboardInterrupt:
        print("\nProgram sonlandırıldı.")
        sys.exit()
