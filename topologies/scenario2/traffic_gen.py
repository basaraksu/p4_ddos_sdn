import sys
import time
import random
import subprocess
import socket
import http.client

# Merkez Sunucular
WEB_SERVER = "10.0.9.1" 
UDP_SERVER = "10.0.9.2" 

def role_sensor_temp():
    """Sıcaklık Sensörü: Rastgele boyutlarda ve Poisson dağılımına göre zamanlanmış UDP verisi atar."""
    print("[+] Sıcaklık Sensörü aktif. (Varyanslı)")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        time.sleep(random.expovariate(1.0 / 7.0))
        extra_payload = b"X" * random.choice([16, 64, 128, 512, 1024, 32, 256])
        sock.sendto(b"TEMP: 24.5C " + extra_payload, (UDP_SERVER, 5001))

def role_sensor_gas():
    """Gaz Sensörü: Daha uzun aralıklarla ama patlamalı (burst) çalışır."""
    print("[+] Gaz Sensörü aktif. (Varyanslı)")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        time.sleep(random.expovariate(1.0 / 12.0))
        burst_count = random.randint(1, 20)
        for _ in range(burst_count):
            sock.sendto(b"GAS: NORMAL", (UDP_SERVER, 5002))
            time.sleep(random.uniform(0.01, 0.05))

def role_camera(target_ip, target_port):
    """Güvenlik Kamerası: Kendisine özel atanmış porttan VBR Akış yollar."""
    print(f"[+] Güvenlik Kamerası aktif. Hedef: {target_ip}:{target_port}")
    time.sleep(random.uniform(2.0, 6.0))
    while True:
        bw = random.randint(50, 500)
        duration = random.randint(10, 30)
        subprocess.run(["iperf3", "-c", target_ip, "-p", str(target_port), "-u", "-b", f"{bw}K", "-t", str(duration)], 
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(random.uniform(3.0, 7.0))

        
def role_human_web():
    """İnsan Kullanıcı: Asla kopmayan (sabit portlu) saf TCP istemcisi."""
    print("[+] Web Kullanıcısı aktif. (Sabit Portlu Raw İstemci)")
    time.sleep(random.uniform(2.0, 5.0))
    
    while True:
        try:
            # Bağlantıyı BİR KERE açıyoruz. Hata vermezse port sonsuza kadar sabit kalır!
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((WEB_SERVER, 8080))
            
            while True: # Bağlantı kopmadığı sürece sadece paket at-çek
                time.sleep(random.expovariate(1.0 / 15.0))
                obj_count = random.randint(2, 6)
                
                for _ in range(obj_count):
                    # GET isteğini at
                    sock.sendall(b"GET / HTTP/1.1\r\nHost: local\r\n\r\n")
                    # Sunucunun 200 OK cevabını bekle (Böylece second_count artar)
                    sock.recv(1024) 
                    time.sleep(random.uniform(0.1, 0.4))
                    
        except Exception as e:
            # Sadece sunucu cidden kapalıysa buraya düşer, bekler ve baştan dener.
            time.sleep(random.uniform(1.0, 3.0))

def role_heavy_tcp(target_ip, target_port):
    """Heavy TCP: Kendisine özel atanmış porttan iPerf dosyası indirir."""
    print(f"[+] Heavy TCP aktif. Hedef: {target_ip}:{target_port}")
    time.sleep(3)
    while True:
        time.sleep(random.expovariate(1.0 / 20.0))
        bw = random.randint(100, 400)
        duration = random.randint(3, 10)
        subprocess.run(["iperf3", "-c", target_ip, "-p", str(target_port), "-b", f"{bw}K", "-t", str(duration)], 
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
def role_ping_client():
    """Bağlantı Kontrol (Ping): Sabit 5 saniye yerine ufak sapmalarla ICMP atar."""
    print("[+] Ping İstemcisi aktif.")
    while True:
        subprocess.run(["ping", "-c", "1", WEB_SERVER], stdout=subprocess.DEVNULL)
        time.sleep(random.uniform(4.0, 8.0))

def role_server_main():
    """Merkez Sunucu: Asla çökmeyen saf (raw) TCP Web (8080) ve Heavy (5201) Sunucusu."""
    print("[+] Merkez Sunucu (Raw TCP Web 8080 & Heavy TCP 5201) başlatıldı.")
    import threading
    import socket

    # 1. HAFİF WEB SUNUCUSU (8080)
    def raw_web_server():
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', 8080))
        server_socket.listen(100)
        
        def handle_client(client_sock):
            while True:
                try:
                    data = client_sock.recv(1024)
                    if not data: break
                    client_sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 512\r\n\r\n" + b"X"*512)
                except: break
            client_sock.close()

        while True:
            client, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(client,), daemon=True).start()

    # 2. AĞIR DOSYA SUNUCUSU (5201 - iPerf yerine)
    def raw_heavy_server():
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', 5201))
        server_socket.listen(100)
        
        def handle_heavy(client_sock):
            while True:
                try:
                    data = client_sock.recv(1024)
                    if not data: break
                    req = data.decode().strip()
                    # İstemci "DOWNLOAD 500000" gibi bir komut atacak
                    if req.startswith("DOWNLOAD"):
                        size = int(req.split()[1])
                        chunk = b"Z" * 4096 # 4KB'lık veri blokları
                        sent = 0
                        while sent < size:
                            client_sock.sendall(chunk)
                            sent += 4096
                except: break
            client_sock.close()

        while True:
            client, addr = server_socket.accept()
            threading.Thread(target=handle_heavy, args=(client,), daemon=True).start()

    # İki sunucuyu da arka planda (Thread) başlat
    threading.Thread(target=raw_web_server, daemon=True).start()
    threading.Thread(target=raw_heavy_server, daemon=True).start()
    while True: time.sleep(100)

def role_server_iot():
    """IoT UDP Sunucusu: Sensörlerden gelen UDP verilerini dinler."""
    print("[+] IoT UDP Sunucusu (5001, 5002) başlatıldı.")
    subprocess.Popen("iperf3 -s > /dev/null 2>&1", shell=True)
    subprocess.Popen("nc -ul -p 5001 > /dev/null 2>&1", shell=True)
    subprocess.Popen("nc -ul -p 5002 > /dev/null 2>&1", shell=True)
    while True: time.sleep(100)
    
def role_noise_generator():
    """Ağa rastgele bağlantı gürültüsü (Noise) katar."""
    print("[+] Gürültü Üretici (Noise Generator) aktif.")
    while True:
        time.sleep(random.uniform(10, 30))
        port_count = random.randint(3, 8)
        for _ in range(port_count):
            rand_port = random.randint(10000, 60000)
            subprocess.run(["nc", "-u", "-w1", WEB_SERVER, str(rand_port)], input=b"ping", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(random.uniform(0.1, 0.5))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım: python3 traffic_gen.py <role> [target_ip] [target_port]")
        sys.exit(1)

    role = sys.argv[1].lower()
    
    # 3. ve 4. argümanlar varsa al, yoksa varsayılanları kullan
    target_ip = sys.argv[2] if len(sys.argv) > 2 else "10.0.9.1"
    target_port = sys.argv[3] if len(sys.argv) > 3 else "5201"
    
    time.sleep(1) 
    
    if role == "sensor_temp": role_sensor_temp()
    elif role == "sensor_gas": role_sensor_gas()
    elif role == "camera": role_camera(target_ip, target_port)
    elif role == "human_web": role_human_web()
    elif role == "heavy_tcp": role_heavy_tcp(target_ip, target_port)
    elif role == "ping_client": role_ping_client()
    elif role == "server_main": role_server_main()
    elif role == "server_iot": role_server_iot()
    elif role == "noise_generator": role_noise_generator()
    else: print(f"Bilinmeyen rol: {role}")