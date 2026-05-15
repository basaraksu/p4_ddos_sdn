import threading
import time
import queue

class BanManagerThread(threading.Thread):
    def __init__(self, controller, daemon=True):
        super().__init__(daemon=daemon)
        self.controller = controller
    ...
    
    def run(self):
        """ ML motorundan kuyruğa düşen IP'leri alır, kendi P4'üne yazar ve ağa fırlatır! """
        while True:
            # Kuyrukta IP yoksa bu thread burada uyur (CPU %0 harcar). IP geldiği salise uyanır!
            malicious_ip = self.controller.ban_queue.get() 
            
            if malicious_ip in self.controller.banned_ips:
                self.controller.ban_queue.task_done()
                continue
            
            # 1. Önce KENDİ mahallemdeki kanamayı durdur (Lokal Drop)
            self.controller.execute_drop_rule(malicious_ip)
            
            # 2. Blokzincir cüzdanımdan bu kararı İMZALA
            signed_tx = self.controller.blockchain.create_signed_transaction(malicious_ip)
            
            # 3. İmzalı paketi diğer kontrolcülere (C2, C3) FIRLAT!
            self.controller.blockchain.broadcast_transaction(signed_tx)
            
            self.controller.ban_queue.task_done()