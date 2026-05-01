import threading
import time
from controller import DDoSController

def start_controller(name, port, device_id):
    print(f"[{name}] Kontrolcü başlatılıyor (Port: {port})...")
    controller = DDoSController(switch_name=name, grpc_port=port, device_id=device_id)
    controller.run()

def main():
    # S1 ve S2 için ayrı iki Thread oluştur
    t1 = threading.Thread(target=start_controller, args=("s1", 50051, 0), daemon=True)
    t2 = threading.Thread(target=start_controller, args=("s2", 50052, 1), daemon=True)

    # Kontrolcüleri aynı anda çalıştır
    t1.start()
    t2.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Sistem kapatılıyor...")

if __name__ == "__main__":
    main()