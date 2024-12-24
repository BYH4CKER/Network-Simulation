from scapy.all import IP, UDP, TCP, send, sr1, sniff, Raw

# Giriş Banner'ı
def giris_banner():
    print("""
    ██████╗ ██████╗  ██████╗ ███╗   ██╗██╗     ██╗███╗   ██╗ ██████╗ 
    ██╔══██╗██╔══██╗██╔═══██╗████╗  ██║██║     ██║████╗  ██║██╔════╝ 
    ██████╔╝██████╔╝██║   ██║██╔██╗ ██║██║     ██║██╔██╗ ██║██║  ███╗
    ██╔═══╝ ██╔═══╝ ██║   ██║██║╚██╗██║██║     ██║██║╚██╗██║██║   ██║
    ██║     ██║     ╚██████╔╝██║ ╚████║███████╗██║██║ ╚████║╚██████╔╝
    ╚═╝     ╚═╝      ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
         🌐 ROUTING PROTOCOL TESPİT ARACI 🌐
                   Yazar: Yiğit
    """)

# Çıkış Banner'ı
def cikis_banner(detected_protocols):
    print("""
    ██████╗ ███████╗██╗██╗     ██╗███████╗████████╗ ██████╗ ██████╗ ███████╗
    ██╔══██╗██╔════╝██║██║     ██║██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝
    ██████╔╝█████╗  ██║██║     ██║███████╗   ██║   ██║   ██║██████╔╝█████╗  
    ██╔═══╝ ██╔══╝  ██║██║     ██║╚════██║   ██║   ██║   ██║██╔═══╝ ██╔══╝  
    ██║     ██║     ██║███████╗██║███████║   ██║   ╚██████╔╝██║     ███████╗
    ╚═╝     ╚═╝     ╚═╝╚══════╝╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝     ╚══════╝
               🎉 BULUNAN PROTOKOLLER 🎉
    """)
    if detected_protocols:
        print("[INFO] Tespit edilen yönlendirme protokolleri:")
        for proto in detected_protocols:
            print(f"   - {proto}")
    else:
        print("[INFO] Hiçbir yönlendirme protokolü tespit edilemedi.")
    print("\n[INFO] Programdan çıkılıyor...")

# OSPF paketi gönder
def send_ospf_packet(target_ip):
    print(f"[INFO] OSPF paketi {target_ip} adresine gönderiliyor...")
    ospf_packet = IP(dst=target_ip, proto=89) / Raw(load="OSPF Test Packet")
    response = sr1(ospf_packet, timeout=3, verbose=False)
    return response is not None

# RIP paketi gönder
def send_rip_packet(target_ip):
    print(f"[INFO] RIP paketi {target_ip} adresine gönderiliyor...")
    rip_packet = IP(dst=target_ip) / UDP(sport=520, dport=520) / Raw(load="RIP Test Packet")
    response = sr1(rip_packet, timeout=3, verbose=False)
    return response is not None

# BGP paketi gönder
def send_bgp_packet(target_ip):
    print(f"[INFO] BGP paketi {target_ip} adresine gönderiliyor...")
    bgp_packet = IP(dst=target_ip) / TCP(dport=179, flags="S")  # TCP SYN Paketi
    response = sr1(bgp_packet, timeout=3, verbose=False)
    return response is not None

# EIGRP paketi gönder
def send_eigrp_packet(target_ip):
    print(f"[INFO] EIGRP paketi {target_ip} adresine gönderiliyor...")
    eigrp_packet = IP(dst=target_ip, proto=88) / Raw(load="EIGRP Test Packet")
    response = sr1(eigrp_packet, timeout=3, verbose=False)
    return response is not None

# Routing protokollerini pasif olarak dinle
def sniff_routing_packets(timeout=30):
    detected_protocols = set()

    def process_packet(packet):
        if packet.haslayer(IP):
            proto = packet[IP].proto
            if proto == 89:  # OSPF
                detected_protocols.add("OSPF")
            elif proto == 88:  # EIGRP
                detected_protocols.add("EIGRP")
            elif proto == 103:  # PIM
                detected_protocols.add("PIM")
            elif proto == 112:  # VRRP
                detected_protocols.add("VRRP")
            elif packet.haslayer(UDP) and packet[UDP].sport == 520:
                detected_protocols.add("RIP")
            elif packet.haslayer(TCP) and packet[TCP].sport == 179:
                detected_protocols.add("BGP")

    print("[INFO] Pasif dinleme başlatıldı...")
    sniff(filter="ip", prn=process_packet, timeout=timeout)
    return list(detected_protocols)

# Ana fonksiyon
def main():
    giris_banner()

    # Kullanıcıdan hedef IP adresini al
    target_ip = input("Hedef cihazın IP adresini girin: ").strip()

    detected_protocols = []

    # OSPF taraması
    if send_ospf_packet(target_ip):
        detected_protocols.append("OSPF")

    # RIP taraması
    if send_rip_packet(target_ip):
        detected_protocols.append("RIP")

    # BGP taraması
    if send_bgp_packet(target_ip):
        detected_protocols.append("BGP")

    # EIGRP taraması
    if send_eigrp_packet(target_ip):
        detected_protocols.append("EIGRP")

    # Pasif dinleme
    passive_protocols = sniff_routing_packets()
    detected_protocols.extend(passive_protocols)

    # Tespit edilen protokoller
    detected_protocols = set(detected_protocols)
    cikis_banner(detected_protocols)

if __name__ == "__main__":
    main()
