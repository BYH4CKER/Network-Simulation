# snmp_mibs.py

# Cisco cihazları için kritik MIB'ler ve açıklamaları
MIBS = {
    "sysDescr": "1.3.6.1.2.1.1.1",  # Cihaz açıklaması
    "sysUpTime": "1.3.6.1.2.1.1.3",  # Çalışma süresi
    "sysName": "1.3.6.1.2.1.1.5",  # Cihaz adı
    "sysLocation": "1.3.6.1.2.1.1.6",  # Cihazın fiziksel konumu
    "sysContact": "1.3.6.1.2.1.1.4",  # Cihaz yöneticisinin iletişim bilgileri
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",  # Ağ arayüz açıklamaları
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",  # Arayüz çalışma durumu
    "ifInOctets": "1.3.6.1.2.1.2.2.1.10",  # Giriş baytları
    "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",  # Çıkış baytları
    "ifInErrors": "1.3.6.1.2.1.2.2.1.14",  # Giriş hataları
    "ifOutErrors": "1.3.6.1.2.1.2.2.1.20",  # Çıkış hataları
    "cpmCPUTotal5min": "1.3.6.1.4.1.9.2.1.58",  # Son 5 dakikalık CPU kullanımı
    "ciscoMemoryPoolUsed": "1.3.6.1.4.1.9.9.48.1.1.1.5",  # Kullanılan bellek
    "ciscoMemoryPoolFree": "1.3.6.1.4.1.9.9.48.1.1.1.6",  # Kullanılabilir bellek
    "ipRouteTable": "1.3.6.1.2.1.4.21",  # Yönlendirme tablosu
    "ciscoEnvMonTemperatureStatusValue": "1.3.6.1.4.1.9.9.117.1.1.1.1.1"  # Çevresel sıcaklık durumu
}
