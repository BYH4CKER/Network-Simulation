import subprocess
from snmp_mibs import MIBS

def check_snmp_port(ip):
    """
    Nmap kullanarak UDP 161 portunun açık olup olmadığını ve SNMP sürüm bilgilerini kontrol eder.
    """
    try:
        print(f"[INFO] {ip} adresinde UDP 161 portu kontrol ediliyor...")
        command = ["nmap", "-sU", "-p", "161", "--script", "snmp-info", ip]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if "161/udp open" in result.stdout:
            print("[OK] UDP 161 portu açık.")
            version_info = None
            for line in result.stdout.split("\n"):
                if "SNMPv" in line:
                    version_info = line.strip()
                    break
            if version_info:
                print(f"[INFO] SNMP Sürümü: {version_info}")
            return True
        else:
            print("[ERROR] UDP 161 portu kapalı.")
            return False
    except Exception as e:
        print(f"[ERROR] Nmap kullanarak port kontrolü sırasında hata: {e}")
        return False

def snmp_query(ip, community):
    """
    SNMP sorgularını belirlenen MIB'ler üzerinden çalıştırır ve sonuçları yazdırır.
    """
    print(f"[INFO] {ip} üzerinde SNMP sorguları başlatılıyor...\n")
    
    for mib_name, mib_oid in MIBS.items():
        try:
            print(f"[QUERY] {mib_name} ({mib_oid}) sorgulanıyor...")
            command = ["snmpwalk", "-v2c", "-c", community, ip, mib_oid]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                print(f"[RESULT] {mib_name}:\n{result.stdout}")
            else:
                print(f"[WARNING] {mib_name} için bilgi alınamadı.")
        except Exception as e:
            print(f"[ERROR] {mib_name} sorgusu sırasında hata: {e}")

def main():
    """
    Kullanıcıdan IP ve community string alarak SNMP işlemleri gerçekleştirir.
    """
    print("SNMP Aracı\n")
    ip = input("Hedef cihazın IP adresini girin: ").strip()
    community = input("SNMP Community String (örn. public): ").strip()

    if check_snmp_port(ip):
        snmp_query(ip, community)
    else:
        print("[ABORT] UDP 161 portu kapalı olduğu için işlem sonlandırıldı.")

if __name__ == "__main__":
    main()
