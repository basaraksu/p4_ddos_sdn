import json
import os

# --- PENTAGON AYARLARI ---
NUM_DOMAINS = 5         # 5 Kontrolcü / 5 Omurga (Core) Switch
SWITCH_PER_DOMAIN = 2   # Her bölgede 2 Edge Switch (Toplam 10 Edge)
HOST_PER_SWITCH = 5     # Her Edge Switch'te 5 Host (Toplam 50 Host)

TOTAL_EDGE_SWITCHES = NUM_DOMAINS * SWITCH_PER_DOMAIN
TOTAL_HOSTS = TOTAL_EDGE_SWITCHES * HOST_PER_SWITCH

OUTPUT_DIR = "generated_jsons"
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def generate():
    topology = {"hosts": {}, "switches": {}, "links": []}
    print(f"[+] {TOTAL_HOSTS} Host, {NUM_DOMAINS + TOTAL_EDGE_SWITCHES} Switch için JSON'lar üretiliyor...")

    # --- 1. SWITCHLERİ TANIMLA ---
    for i in range(1, NUM_DOMAINS + 1):
        sw_name = f"cs{i}"
        topology["switches"][sw_name] = {"runtime_json": f"{sw_name}-runtime.json"}

    for i in range(1, TOTAL_EDGE_SWITCHES + 1):
        sw_name = f"s{i}"
        topology["switches"][sw_name] = {"runtime_json": f"{sw_name}-runtime.json"}

    # --- 2. FİZİKSEL BAĞLANTILARI (LINKS) OLUŞTUR ---
    # Core <-> Core Ring (Halka) Bağlantısı (cs1->cs2->cs3->cs4->cs5->cs1)
    # Port 1: Saat yönünün tersi (Sol), Port 2: Saat yönü (Sağ)
    for i in range(1, NUM_DOMAINS + 1):
        next_i = (i % NUM_DOMAINS) + 1
        topology["links"].append([f"cs{i}-p2", f"cs{next_i}-p1"])

    host_counter = 1
    # Edge <-> Core ve Host <-> Edge Bağlantıları
    for i in range(1, TOTAL_EDGE_SWITCHES + 1):
        domain_id = ((i - 1) // SWITCH_PER_DOMAIN) + 1
        core_sw = f"cs{domain_id}"
        edge_sw = f"s{i}"
        
        # Edge switch'ler Core'a Port 3 ve Port 4'ten bağlanır
        core_port = ((i - 1) % SWITCH_PER_DOMAIN) + 3 
        topology["links"].append([f"{edge_sw}-p1", f"{core_sw}-p{core_port}"])

        for h in range(1, HOST_PER_SWITCH + 1):
            h_name = f"h{host_counter}"
            h_ip = f"10.0.{i}.{h}"
            h_mac = f"08:00:00:00:{i:02x}:{h:02x}"
            gw_ip = f"10.0.{i}.100"
            gw_mac = f"08:00:00:00:{i:02x}:00"
            
            # --- GÖREV ATAMA ALGORİTMASI (50 Host Port Mimarisi) ---
            traffic_cmd = ""
            server_extra_cmds = [] # Sunucuların açacağı özel iperf kapıları
            
            # 1. SUNUCULARI BELİRLE (Veri Merkezi - Domain 5)
            if host_counter == 41: 
                traffic_cmd = "python3 traffic_gen.py server_main &" # 10.0.9.1
                # Heavy TCP'ler (Host 26, 27, 28, 29) için kapıları aç
                for h_id in range(26, 30):
                    server_extra_cmds.append(f"iperf3 -s -p 50{h_id:02d} -D")
                    
            elif host_counter == 42: 
                traffic_cmd = "python3 traffic_gen.py server_iot &"  # 10.0.9.2
                # Kameralar (Host 17, 18, 19) için kapıları aç
                for h_id in range(17, 20):
                    server_extra_cmds.append(f"iperf3 -s -p 50{h_id:02d} -D")
            
            # 2. UYUYAN ZOMBİLER
            elif host_counter in [10, 20, 30, 40, 50]: 
                traffic_cmd = ""
                
            # 3. İSTEMCİLER (Özel Port Atamalarıyla)
            elif 1 <= host_counter <= 9: # Domain 1 (Sanayi)
                traffic_cmd = "python3 traffic_gen.py sensor_temp &" if host_counter <= 4 else "python3 traffic_gen.py sensor_gas &"
                
            elif 11 <= host_counter <= 19: # Domain 2 (Konut)
                if host_counter <= 16: 
                    traffic_cmd = "python3 traffic_gen.py human_web &" 
                else: # Kameralar kendi özel portuna yolluyor (Örn: 5017, 5018, 5019)
                    traffic_cmd = f"python3 traffic_gen.py camera 10.0.9.2 50{host_counter:02d} &"
                    
            elif 21 <= host_counter <= 29: # Domain 3 (Hastane/Kamu)
                if host_counter <= 25: 
                    traffic_cmd = "python3 traffic_gen.py human_web &" 
                else: # Heavy TCP'ler kendi özel portuna yolluyor (Örn: 5026, 5027, 5028, 5029)
                    traffic_cmd = f"python3 traffic_gen.py heavy_tcp 10.0.9.1 50{host_counter:02d} &"
                    
            elif 31 <= host_counter <= 39: # Domain 4 (Finans)
                traffic_cmd = "python3 traffic_gen.py human_web &" if host_counter <= 35 else "python3 traffic_gen.py ping_client &"
                
            elif 43 <= host_counter <= 49: # Domain 5 (Veri Merkezi Gürültüsü)
                traffic_cmd = "python3 traffic_gen.py noise_generator &"

            # Başlangıç komutları (Gateway, ARP)
            cmds = [
                "sysctl -w net.ipv6.conf.all.disable_ipv6=1",
                f"route add default gw {gw_ip} dev eth0",
                f"arp -i eth0 -s {gw_ip} {gw_mac}"
            ]
            
            # Komşuları ARP tablolarına ekle
            for neighbor_h in range(1, HOST_PER_SWITCH + 1):
                if neighbor_h != h: 
                    n_ip = f"10.0.{i}.{neighbor_h}"
                    n_mac = f"08:00:00:00:{i:02x}:{neighbor_h:02x}"
                    cmds.append(f"arp -i eth0 -s {n_ip} {n_mac}")
            
            # Sunuculara özel kapı komutlarını ekle
            cmds.extend(server_extra_cmds)
            
            # Ana trafiği başlat
            if traffic_cmd: cmds.append(traffic_cmd)

            topology["hosts"][h_name] = {"ip": f"{h_ip}/24", "mac": h_mac, "commands": cmds}
            topology["links"].append([h_name, f"{edge_sw}-p{h+1}"])
            host_counter += 1

    with open(f"{OUTPUT_DIR}/topology.json", "w") as f:
        json.dump(topology, f, indent=4)

    # --- 3. RUNTIME (KURALLAR) JSON'LARINI OLUŞTUR ---
    base_runtime = {
        "target": "bmv2", "p4info": "build/ddos_detection.p4.p4info.txtpb", "bmv2_json": "build/ddos_detection.json", "table_entries": []
    }

    # EDGE Switch Kuralları (s1 ... s10)
    for i in range(1, TOTAL_EDGE_SWITCHES + 1):
        rt = base_runtime.copy()
        rt["table_entries"] = []
        for h in range(1, HOST_PER_SWITCH + 1): # Yerel ağ hedefleri
            rt["table_entries"].append({
                "table": "MyIngress.ipv4_lpm", "match": { "hdr.ipv4.dstAddr": [f"10.0.{i}.{h}", 32] },
                "action_name": "MyIngress.ipv4_forward", "action_params": { "dstAddr": f"08:00:00:00:{i:02x}:{h:02x}", "port": h+1 }
            })
        # Dışarı giden trafiği Core'a (Port 1) at
        rt["table_entries"].append({
            "table": "MyIngress.ipv4_lpm", "match": { "hdr.ipv4.dstAddr": ["10.0.0.0", 8] },
            "action_name": "MyIngress.ipv4_forward", "action_params": { "dstAddr": f"08:00:00:00:{i:02x}:00", "port": 1 }
        })
        with open(f"{OUTPUT_DIR}/s{i}-runtime.json", "w") as f: json.dump(rt, f, indent=4)

    # CORE Switch Runtime Kuralları (cs1 ... cs5)
    for c_id in range(1, NUM_DOMAINS + 1):
        rt = base_runtime.copy()
        rt["table_entries"] = []
        
        # 1. Kendi altındaki Edge Switch'lere giden trafik (Port 3 ve 4)
        start_subnet = (c_id - 1) * SWITCH_PER_DOMAIN + 1
        for offset in range(SWITCH_PER_DOMAIN):
            subnet = start_subnet + offset
            port = offset + 3
            rt["table_entries"].append({
                "table": "MyIngress.ipv4_lpm", "match": { "hdr.ipv4.dstAddr": [f"10.0.{subnet}.0", 24] },
                "action_name": "MyIngress.ipv4_forward", "action_params": { "dstAddr": f"08:00:00:00:{subnet:02x}:00", "port": port }
            })
            
        # 2. Diğer Omurgalara Yönlendirme (Ring Mantığı)
        for other_d in range(1, NUM_DOMAINS + 1):
            if other_d == c_id: continue
            
            # En kısa yolu bul (Sağa mı gideyim, sola mı?)
            clockwise_dist = (other_d - c_id) % NUM_DOMAINS
            port = 2 if clockwise_dist <= 2 else 1

            start_ip = (other_d - 1) * SWITCH_PER_DOMAIN + 1
            for offset in range(SWITCH_PER_DOMAIN):
                sub = start_ip + offset
                rt["table_entries"].append({
                    "table": "MyIngress.ipv4_lpm", "match": { "hdr.ipv4.dstAddr": [f"10.0.{sub}.0", 24] },
                    "action_name": "MyIngress.ipv4_forward", "action_params": { "dstAddr": "08:00:00:00:cc:cc", "port": port }
                })

        with open(f"{OUTPUT_DIR}/cs{c_id}-runtime.json", "w") as f: json.dump(rt, f, indent=4)
            
    print("[+] BÜTÜN DOSYALAR BAŞARIYLA ÜRETİLDİ!")

if __name__ == "__main__":
    generate()