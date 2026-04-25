from scapy.all import *
import threading
import time
import queue

class CSVThread(threading.Thread):
    def __init__(self, switch, controller, daemon=True):
        super().__init__(daemon=daemon)
        self.switch = switch
        self.controller = controller
        self.csv_file = f"{self.switch.name}_data.csv"
        
        
    def run(self):
        print(f"--- {self.switch.name} Digest verileri dinleniyor... ---")
        while True:
            try:
                # data al
                data = self.controller.q_digest.get()
                
                if not data:
                    continue
                
                """ CSV dosyasına yazma işlemi """
                with open(self.csv_file, 'a') as f:
                    # Eğer dosya yeni oluşturulmuşsa başlık ekle
                    if f.tell() == 0:
                        f.write("flow_id,fwd_count,bwd_count,duration,packet_size_sum,min_packet_size,max_packet_size,iat_sum,iat_sum_square,min_iat,max_iat\n")
                    # Veriyi CSV formatında yaz
                    f.write(f"{data['flow_id']},{data['fwd_count']},{data['bwd_count']},{data['duration']},{data['packet_size_sum']},{data['min_packet_size']},{data['max_packet_size']},{data['iat_sum']},{data['iat_sum_square']},{data['min_iat']},{data['max_iat']}\n")
                        
            except Exception as e:
                print(f"CSV Hatası: {e}")
                time.sleep(1) # Hata durumunda döngüyü yavaşlat
    ...