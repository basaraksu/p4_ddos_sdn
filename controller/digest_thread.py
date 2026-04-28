from scapy.all import *
import threading
import time
import queue

class DigestThread(threading.Thread):
    def __init__(self, switch, controller, daemon=True):
        super().__init__(daemon=daemon)
        self.switch = switch
        self.controller = controller
        
        
    def run(self):
        print(f"--- {self.switch.name} Digest verileri dinleniyor... ---")
        while True:
            try:
                # Digest mesajını al
                digest_msg = self.switch.Digest()
                
                if not digest_msg:
                    continue
                
                

                for item in digest_msg.data:
                    members = item.struct.members
                    
                    stats = {
                       'flow_id': int.from_bytes(members[0].bitstring, 'big'),
                       'first_ip': int.from_bytes(members[1].bitstring, 'big'),
                       'second_ip': int.from_bytes(members[2].bitstring, 'big'),
                       'src_port': int.from_bytes(members[3].bitstring, 'big'),
                       'dst_port': int.from_bytes(members[4].bitstring, 'big'),
                       'protocol': int.from_bytes(members[5].bitstring, 'big'),
                       'fwd_count': int.from_bytes(members[6].bitstring, 'big'),
                       'bwd_count': int.from_bytes(members[7].bitstring, 'big'),
                       'packet_size_sum': int.from_bytes(members[8].bitstring, 'big'),
                       'duration': int.from_bytes(members[9].bitstring, 'big')
                    }
                    
                    print(f"--- Digest alindi: {stats['flow_id']} ---")
                    #print(f"--- Digest detaylari: {stats} ---")

                    # Kuyruğa ekle (Doluysa bekleme, geç - Opsiyonel)
                    try:
                        self.controller.q_digest.put(stats, block=False)
                    except:
                        # Kuyruk doluysa en eski veriyi atmak için mantık eklenebilir
                        pass
                        
            except Exception as e:
                print(f"Digest Hatası: {e}")
                time.sleep(1) # Hata durumunda döngüyü yavaşlat
    ...