from controller import DDoSController
import time
import warnings
warnings.filterwarnings("ignore")
def main():
    # Domain 1 (C1): cs1, s1, s2
    domain1_switches = [
        {"name": "cs1", "grpc_port": 50051, "device_id": 0},
        {"name": "s1",  "grpc_port": 50056, "device_id": 5},
        {"name": "s2",  "grpc_port": 50057, "device_id": 6}
    ]
    domain1_peers = [6002, 6003, 6004, 6005]  # C2, C3, C4, C5 ile konuşacak
    c1 = DDoSController("C1", domain1_switches, "features_c1.csv", p2p_port=6001, peers=domain1_peers, controllers_in_network=["C1", "C2", "C3", "C4", "C5"])

    # Domain 2 (C2): cs2, s3, s4
    domain2_switches = [
        {"name": "cs2", "grpc_port": 50052, "device_id": 1},
        {"name": "s3",  "grpc_port": 50058, "device_id": 7},
        {"name": "s4",  "grpc_port": 50059, "device_id": 8}
    ]
    domain2_peers = [6001, 6003, 6004, 6005]
    c2 = DDoSController("C2", domain2_switches, "features_c2.csv", p2p_port=6002, peers=domain2_peers, controllers_in_network=["C1", "C2", "C3", "C4", "C5"])

    # Domain 3 (C3): cs3, s5, s6
    domain3_switches = [
        {"name": "cs3", "grpc_port": 50053, "device_id": 2},
        {"name": "s5",  "grpc_port": 50060, "device_id": 9},
        {"name": "s6",  "grpc_port": 50061, "device_id": 10}
    ]
    domain3_peers = [6001, 6002, 6004, 6005]
    c3 = DDoSController("C3", domain3_switches, "features_c3.csv", p2p_port=6003, peers=domain3_peers, controllers_in_network=["C1", "C2", "C3", "C4", "C5"])

    # Domain 4 (C4): cs4, s7, s8
    domain4_switches = [
        {"name": "cs4", "grpc_port": 50054, "device_id": 3},
        {"name": "s7",  "grpc_port": 50062, "device_id": 11},
        {"name": "s8",  "grpc_port": 50063, "device_id": 12}
    ]
    domain4_peers = [6001, 6002, 6003, 6005]
    c4 = DDoSController("C4", domain4_switches, "features_c4.csv", p2p_port=6004, peers=domain4_peers, controllers_in_network=["C1", "C2", "C3", "C4", "C5"])

    # Domain 5 (C5): cs5, s9, s10
    domain5_switches = [
        {"name": "cs5", "grpc_port": 50055, "device_id": 4},
        {"name": "s9",  "grpc_port": 50064, "device_id": 13},
        {"name": "s10", "grpc_port": 50065, "device_id": 14}
    ]
    domain5_peers = [6001, 6002, 6003, 6004]
    c5 = DDoSController("C5", domain5_switches, "features_c5.csv", p2p_port=6005, peers=domain5_peers, controllers_in_network=["C1", "C2", "C3", "C4", "C5"])                   

    controllers = [c1, c2, c3, c4, c5]
    for c in controllers:
        c.start()
        time.sleep(0.5)

    print("\n[SENARYO 2 SİSTEM AKTİF] 5 Kontrolcü, 15 Switch dinleniyor.")
    while True: time.sleep(10)

if __name__ == '__main__':
    main()