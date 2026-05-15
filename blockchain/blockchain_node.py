import json
import hashlib
import rsa
import time
import threading
import socket

class BlockchainNode:
    def __init__(self, node_id, host, port, peers, controller):
        self.node_id = node_id
        self.host = host          # Örn: '127.0.0.1'
        self.port = port          # Bu kontrolcünün dinleyeceği port (Örn: C1 için 6001)
        self.peers = peers        # Diğer kontrolcülerin port listesi (Örn: [6002, 6003])
        self.controller = controller  # Ana kontrolcü nesnesi (P4 kaslarına erişim için)

        self.chain = []       
        self.mempool = []     
        
        print(f"[{self.node_id}] Kriptografik anahtarlar (RSA-512) üretiliyor...")
        self.public_key, self.private_key = rsa.newkeys(512)
        
        self.create_genesis_block()
        
        # --- AĞ HABERLEŞMESİ (P2P) THREAD'İNİ BAŞLAT ---
        self.server_thread = threading.Thread(target=self.start_listening, daemon=True)
        self.server_thread.start()
        
        # --- MADENCİ (KONSENSÜS) THREAD'İNİ BAŞLAT ---
        self.start_miner_thread()

    def create_genesis_block(self):
        genesis_block = {
            'index': 0,
            'timestamp': 0,
            'transactions': [],
            'previous_hash': "0" * 64,  # İlk blok olduğu için öncesi yok
            'miner': "SYSTEM"
        }
        self.chain.append(genesis_block)
        print(f"[{self.node_id}] Genesis (Sıfırıncı) Blok oluşturuldu.")

    # =================================================================
    # İŞLEM (TRANSACTION) OLUŞTURMA VE DOĞRULAMA
    # =================================================================

    def create_signed_transaction(self, malicious_ip):
        """ ML Motoru saldırgan bulduğunda JSON oluşturur ve İmzalar. """
        tx_data = {
            'ip_to_ban': malicious_ip,
            'sender': self.node_id,
            'timestamp': time.time()
        }

        tx_string = json.dumps(tx_data, sort_keys=True).encode('utf-8')
        signature = rsa.sign(tx_string, self.private_key, 'SHA-256')

        signed_tx = {
            'data': tx_data,
            'signature': signature.hex(), 
            'public_key': self.public_key.save_pkcs1().decode('utf-8') 
        }
        
        print(f"[{self.node_id}] {malicious_ip} için Ban Talebi İMZALANDI.")
        return signed_tx

    def verify_and_add_to_mempool(self, signed_tx):
        """ Dışarıdan gelen bir işlemi havuza almadan önce imzasını doğrular. """
        try:
            tx_data = signed_tx['data']
            signature = bytes.fromhex(signed_tx['signature'])
            sender_pub_key = rsa.PublicKey.load_pkcs1(signed_tx['public_key'].encode('utf-8'))

            tx_string = json.dumps(tx_data, sort_keys=True).encode('utf-8')
            rsa.verify(tx_string, signature, sender_pub_key)
            
            is_duplicate = any(tx['ip_to_ban'] == tx_data['ip_to_ban'] for tx in self.mempool)
            
            if not is_duplicate:
                self.mempool.append(tx_data)
                print(f"[{self.node_id}] İmza DOĞRULANDI! {tx_data['ip_to_ban']} Mempool'a eklendi.")
                
            return True

        except rsa.VerificationError:
            print(f"[{self.node_id}] 🚨 GÜVENLİK İHLALİ: Geçersiz Tx İmzası! İşlem reddedildi.")
            return False
            
    # =================================================================
    # P2P HABERLEŞME KASLARI (SİNİR SİSTEMİ)
    # =================================================================

    def start_listening(self):
        """ [SUNUCU] Bu kontrolcünün portunu sürekli dinler. """
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"[{self.node_id}] P2P Ağı Dinleniyor... (Port: {self.port})")
        
        while True:
            try:
                client_socket, address = server_socket.accept()
                threading.Thread(target=self.handle_incoming_message, args=(client_socket,), daemon=True).start()
            except Exception as e:
                print(f"[{self.node_id}] Dinleme Hatası: {e}")

    def handle_incoming_message(self, client_socket):
        """ Gelen TCP paketini okur, Transaction veya Blok olmasına göre yönlendirir. """
        try:
            data = client_socket.recv(8192).decode('utf-8') # Bloklar büyük olabilir, buffer'ı 8192 yaptık
            if data:
                message = json.loads(data)
                
                if message.get('type') == 'TRANSACTION':
                    self.verify_and_add_to_mempool(message['payload'])
                    
                elif message.get('type') == 'BLOCK':
                    self.handle_incoming_block(message['payload']) 
                    
        except Exception as e:
            print(f"[{self.node_id}] Mesaj İşleme Hatası: {e}")
        finally:
            client_socket.close()

    def broadcast_transaction(self, signed_tx):
        """ [İSTEMCİ] İmzalı işlemi (Tx) ağdaki tüm kontrolcülere fırlatır. """
        network_message = {
            'type': 'TRANSACTION',
            'payload': signed_tx
        }
        message_bytes = json.dumps(network_message).encode('utf-8')

        for peer_port in self.peers:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((self.host, peer_port))
                s.sendall(message_bytes)
                s.close()
                print(f"[{self.node_id}] -> Tx Port {peer_port}'a fırlatıldı!")
            except ConnectionRefusedError:
                pass # Karşı taraf kapalıysa yola devam
            except Exception:
                pass
                
    def broadcast_block(self, new_block, signature):
        """ [İSTEMCİ] Oluşturulan İMZALI bloğu P2P ağındaki herkese fırlatır. """
        network_message = {
            'type': 'BLOCK',
            'payload': {
                'block_data': new_block,
                'signature': signature.hex(),
                'public_key': self.public_key.save_pkcs1().decode('utf-8')
            }
        }
        message_bytes = json.dumps(network_message).encode('utf-8')

        for peer_port in self.peers:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((self.host, peer_port))
                s.sendall(message_bytes)
                s.close()
                print(f"[{self.node_id}] -> 📦 Blok Port {peer_port}'a fırlatıldı!")
            except Exception:
                pass 
    
    # =================================================================
    # MADENCİ (MINER) VE KONSENSÜS KASLARI
    # =================================================================

    def start_miner_thread(self):
        """ Arka planda 1 saniyede bir uyanıp Mempool'u kontrol eden Madenci """
        threading.Thread(target=self.mine_block, daemon=True).start()

    def mine_block(self):
        # Lider sırasını hesaplamak için ağdaki tüm node'ların sıralı listesi
        # NOT: self.controller içinde "controllers_in_network" diye bir liste (örn: ["C1", "C2", "C3"]) olmalı.
        node_order = self.controller.controllers_in_network  
        
        while True:
            time.sleep(1) # 1 saniyelik blok süresi (Block Time)
            
            if not self.mempool:
                continue
                
            # LİDER SEÇİMİ (Proof of Authority - Round Robin)
            next_block_index = len(self.chain)
            leader_index = next_block_index % len(node_order)
            leader_node = node_order[leader_index]
            
            if self.node_id == leader_node:
                print(f"[{self.node_id}] 👑 SIRA BENDE! Mempool'daki {len(self.mempool)} işlem BLOK yapılıyor...")
                
                # 1. Havuzdaki verilerle yeni blok oluştur
                new_block = {
                    'index': next_block_index,
                    'timestamp': time.time(),
                    'transactions': list(self.mempool),
                    'previous_hash': self.hash_block(self.chain[-1]), 
                    'miner': self.node_id
                }
                
                # 2. Bloğu İmzala
                block_string = json.dumps(new_block, sort_keys=True).encode('utf-8')
                block_signature = rsa.sign(block_string, self.private_key, 'SHA-256')
                
                # 3. Kendi defterime yaz
                self.chain.append(new_block)
                
                # 4. RACE CONDITION ÇÖZÜMÜ: Sadece bu bloğa eklediğim IP'leri havuzdan çıkar
                block_ips = [tx['ip_to_ban'] for tx in new_block['transactions']]
                self.mempool = [tx for tx in self.mempool if tx['ip_to_ban'] not in block_ips]
                
                # 5. Kendi P4 kaslarımı çalıştır
                self.apply_block_rules(new_block)
                
                # 6. AĞA FIRLAT!
                self.broadcast_block(new_block, block_signature)

    def hash_block(self, block):
        """ Bir bloğun SHA-256 şifresini çıkarır. """
        block_string = json.dumps(block, sort_keys=True).encode('utf-8')
        return hashlib.sha256(block_string).hexdigest()

    def handle_incoming_block(self, block_payload):
        """ Dışarıdan gelen bir Bloğu alır, İMZASINI doğrular ve deftere işler. """
        new_block = block_payload['block_data']
        signature = bytes.fromhex(block_payload['signature'])
        miner_pub_key = rsa.PublicKey.load_pkcs1(block_payload['public_key'].encode('utf-8'))
        
        # 0. GÜVENLİK KONTROLÜ: Bloğun İmzası Doğru mu?
        try:
            block_string = json.dumps(new_block, sort_keys=True).encode('utf-8')
            rsa.verify(block_string, signature, miner_pub_key)
        except rsa.VerificationError:
            print(f"[{self.node_id}] 🚨 KRİTİK GÜVENLİK: Sahte Blok Tespit Edildi! İmza geçersiz!")
            return False

        # 1. Kriptografik Kontrol: Önceki bloğun hash'i tutuyor mu?
        last_block = self.chain[-1]
        if new_block['previous_hash'] != self.hash_block(last_block):
            print(f"[{self.node_id}] ❌ REDDEDİLDİ! Gelen bloğun Hash'i bozuk (Zincir uyuşmazlığı)!")
            return False
            
        # 2. Bloğu deftere ekle
        self.chain.append(new_block)
        
        # 3. Gelen bloktaki işlemler havuzumdaysa onları temizle (Race Condition engeli)
        block_ips = [tx['ip_to_ban'] for tx in new_block['transactions']]
        self.mempool = [tx for tx in self.mempool if tx['ip_to_ban'] not in block_ips]
        
        print(f"[{self.node_id}] 🔗 YENİ BLOK KABUL EDİLDİ! (Blok No: {new_block['index']})")
        
        # 4. P4 Kaslarını Çalıştır
        self.apply_block_rules(new_block)
        return True

    def apply_block_rules(self, block):
        """ Bloktaki IP'leri okur, Controller üzerinden DROP kuralı yazar """
        for tx in block['transactions']:
            ip = tx['ip_to_ban']
            self.controller.execute_drop_rule(ip)