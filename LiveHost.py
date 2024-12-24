import os
import ipaddress
from scapy.all import ARP, Ether, srp, sniff

def get_network_interfaces():
    """
    Mevcut ağ arayüzlerini ve detaylarını sistem komutlarıyla listeler.
    """
    interfaces = []
    try:
        # Linux ve Mac için 'ip' komutunu kullan
        result = os.popen("ip -4 addr show").read()
        lines = result.split("\n")

        for line in lines:
            if "inet " in line:
                parts = line.split()
                ip_cidr = parts[1]  # Örneğin, '192.168.1.100/24'
                interface = parts[-1]  # Arayüz adı, örn. 'eth0'
                
                # CIDR formatından ağ aralığını ve netmask'i ayır
                ip_network = ipaddress.ip_network(ip_cidr, strict=False)
                interfaces.append({
                    "interface": interface,
                    "ip": str(ip_network.network_address),
                    "netmask": str(ip_network.netmask),
                    "network": str(ip_network)
                })

    except Exception as e:
        print(f"[ERROR] Ağ arayüzlerini tespit ederken bir hata oluştu: {e}")
    return interfaces

def icmp_ping(ip):
    """
    Belirli bir IP adresine ICMP ping gönderir.
    """
    response = os.system(f"ping -c 1 -w 1 {ip} > /dev/null 2>&1")
    return response == 0

def scan_network_with_icmp(network):
    """
    ICMP ping kullanarak ağdaki cihazları tarar.
    """
    print(f"[INFO] {network} ağında ICMP taraması yapılıyor...")
    devices = []
    for ip in ipaddress.IPv4Network(network).hosts():
        if icmp_ping(str(ip)):
            devices.append({'ip': str(ip), 'mac': 'N/A'})
    return devices

def scan_network_with_arp(network):
    """
    ARP istekleri kullanarak ağdaki cihazları tarar.
    """
    print(f"[INFO] {network} ağında ARP taraması yapılıyor...")
    devices = []
    try:
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        answered_list = srp(arp_request_broadcast, timeout=5, verbose=False)[0]

        for sent, received in answered_list:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    except Exception as e:
        print(f"[ERROR] ARP taraması sırasında bir hata oluştu: {e}")
    return devices

def passive_scan(timeout=20):
    """
    Ağ trafiğini dinleyerek cihazları tespit eder.
    """
    print("[INFO] Pasif tarama başlatıldı...")

    devices = []

    def process_packet(packet):
        if packet.haslayer(ARP) and packet.op == 2:  # ARP Reply
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            if ip not in [device['ip'] for device in devices]:
                devices.append({'ip': ip, 'mac': mac})
                print(f"Bulundu: IP={ip}, MAC={mac}")

    sniff(filter="arp", prn=process_packet, timeout=timeout)
    return devices

def merge_devices(*device_lists):
    """
    Farklı tarama yöntemlerinden gelen cihaz listelerini birleştirir.
    """
    merged_devices = []
    for device_list in device_lists:
        for device in device_list:
            if device['ip'] not in [d['ip'] for d in merged_devices]:
                merged_devices.append(device)
    return merged_devices

def display_devices(devices):
    """
    Bulunan cihazların IP ve MAC adreslerini ekrana yazdırır.
    """
    if devices:
        print("\n[INFO] Bulunan Cihazlar:")
        for index, device in enumerate(devices, start=1):
            print(f"{index}. IP: {device['ip']} | MAC: {device['mac']}")
    else:
        print("\n[INFO] Ağda hiçbir cihaz bulunamadı.")

def main():
    print("Mevcut Ağ Arayüzleri:\n")

    # Mevcut ağ arayüzlerini ve detaylarını listeler
    interfaces = get_network_interfaces()
    if not interfaces:
        print("[ERROR] Hiçbir aktif ağ arayüzü tespit edilemedi. Lütfen bağlantınızı kontrol edin.")
        exit()

    for i, iface in enumerate(interfaces, start=1):
        print(f"{i}. Arayüz: {iface['interface']}")
        print(f"   IP: {iface['ip']}")
        print(f"   Netmask: {iface['netmask']}")
        print(f"   Ağ Aralığı: {iface['network']}\n")

    # Kullanıcıdan tarama için ağ aralığını al
    selected_network = input("Tarama yapmak istediğiniz ağ aralığını girin (örn. 192.168.1.0/24): ").strip()

    try:
        # ICMP tarama
        icmp_devices = scan_network_with_icmp(selected_network)

        # ARP tarama
        arp_devices = scan_network_with_arp(selected_network)

        # Pasif tarama
        passive_devices = passive_scan(timeout=20)

        # Tüm cihazları birleştir
        all_devices = merge_devices(icmp_devices, arp_devices, passive_devices)

        # Sonuçları ekrana yazdır
        display_devices(all_devices)

    except KeyboardInterrupt:
        print("\n[INFO] Program sonlandırıldı.")
    except ValueError as ve:
        print(f"[ERROR] Geçersiz ağ aralığı girdiniz: {ve}")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()
