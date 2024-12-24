from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sniff, sendp, get_if_raw_hwaddr
import threading
import sys
import time

# Tespit edilen DHCP sunucularını saklamak için global liste
tespit_edilen_sunucular = []
calisiyor = True

# Giriş Banner'ı
def giris_banner():
    print("""
    ██████╗  ██████╗ ██╗  ██╗██████╗     ██████╗██╗  ██╗███████╗
    ██╔══██╗██╔═══██╗██║ ██╔╝██╔══██╗   ██╔════╝██║  ██║██╔════╝
    ██████╔╝██║   ██║█████╔╝ ██████╔╝   ██║     ███████║█████╗  
    ██╔═══╝ ██║   ██║██╔═██╗ ██╔═══╝    ██║     ██╔══██║██╔══╝  
    ██║     ╚██████╔╝██║  ██╗██║        ╚██████╗██║  ██║███████╗
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝         ╚═════╝╚═╝  ╚═╝╚══════╝
                🚀 DHCP TESPİT ARACI 🚀
                   Yazar: Yiğit
    """)

# DHCP Discover paketini gönder
def dhcp_discover_gonder(arayuz):
    """
    Belirtilen ağ arayüzüne DHCP Discover paketi gönderir.
    """
    hw = get_if_raw_hwaddr(arayuz)[1]  # Arayüzün donanım adresini (MAC) alır
    dhcp_discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=hw) /
        DHCP(options=[("message-type", "discover"), "end"])
    )
    sendp(dhcp_discover, iface=arayuz, verbose=0)
    print(f"DHCP Discover paketi gönderildi: {arayuz}")

# DHCP paketlerini tespit et
def dhcp_paketlerini_tespit_et(paket):
    """
    Gelen DHCP paketlerini işleyen geri çağırma fonksiyonu.
    """
    global calisiyor
    if paket.haslayer(DHCP):
        mac_adresi = paket[Ether].src
        ip_adresi = paket[IP].src
        
        # Yeni bir DHCP sunucusu tespit edilirse listeye ekle
        if (ip_adresi, mac_adresi) not in tespit_edilen_sunucular:
            tespit_edilen_sunucular.append((ip_adresi, mac_adresi))
            print(f"DHCP Sunucusu Tespit Edildi! IP Adresi: {ip_adresi}, MAC Adresi: {mac_adresi}")
            calisiyor = False  # Sunucu bulunduğunda dinlemeyi durdur

# DHCP paketlerini dinle
def dhcp_dinle(arayuz):
    """
    DHCP paketlerini sürekli olarak dinler.
    """
    print(f"{arayuz} arayüzünde DHCP paketlerini dinliyorum...")
    while calisiyor:
        sniff(filter="udp and (port 67 or port 68)", iface=arayuz, prn=dhcp_paketlerini_tespit_et, store=0, timeout=10)
        time.sleep(1)

# DHCP Discover paketlerini düzenli olarak gönder
def dhcp_discover_duzenli_gonder(arayuz):
    """
    Her 40 saniyede bir DHCP Discover paketleri gönderir.
    """
    while calisiyor:
        dhcp_discover_gonder(arayuz)
        time.sleep(40)

# Çıkış Banner'ı
def cikis_banner():
    print("""
    ██████╗  █████╗ ██████╗ ███████╗██╗   ██╗██████╗ ███████╗██████╗ 
    ██╔══██╗██╔══██╗██╔══██╗██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗
    ██████╔╝███████║██████╔╝█████╗  ██║   ██║██████╔╝█████╗  ██████╔╝
    ██╔═══╝ ██╔══██║██╔═══╝ ██╔══╝  ██║   ██║██╔═══╝ ██╔══╝  ██╔═══╝ 
    ██║     ██║  ██║██║     ███████╗╚██████╔╝██║     ███████╗██║     
    ╚═╝     ╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝     
              🎉 DHCP Sunucuları Bulundu! 🎉
    """)

# Ana fonksiyon
def main():
    global calisiyor

    # Giriş Banner'ını göster
    giris_banner()

    # Ağ arayüzünü belirt
    arayuz = input("Ağ arayüzünü girin (ör. eth0, wlan0): ").strip()

    # Dinleme thread'i başlat
    dinleme_thread = threading.Thread(target=dhcp_dinle, args=(arayuz,), daemon=True)
    dinleme_thread.start()

    # DHCP Discover gönderme thread'i başlat
    discover_thread = threading.Thread(target=dhcp_discover_duzenli_gonder, args=(arayuz,), daemon=True)
    discover_thread.start()

    try:
        while calisiyor:
            time.sleep(1)  # Ana döngü devam ederken bekler
        dinleme_thread.join()
        discover_thread.join()
        cikis_banner()
        print("\nTespit Edilen DHCP Sunucuları:")
        for ip, mac in tespit_edilen_sunucular:
            print(f"IP Adresi: {ip}, MAC Adresi: {mac}")
        sys.exit()
    except KeyboardInterrupt:
        print("\nProgram kullanıcı tarafından durduruldu.")
        calisiyor = False
        dinleme_thread.join()
        discover_thread.join()
        sys.exit()

if __name__ == "__main__":
    main()
