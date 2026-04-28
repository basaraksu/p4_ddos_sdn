from scapy.all import *
import pandas as pd

def discover_host(controller, target_ip, ingress_port, sender_mac, sender_ip):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=sender_mac) / \
            ARP(op=1, hwsrc=sender_mac, psrc=sender_ip, pdst=target_ip)

    # Paketin geldiği port haric tüm aktif portlara gönder
    for port in controller.active_ports:
        if port != ingress_port:
            send_packet_out(controller, port, pkt)
...
    
    
def send_packet_out(controller, egress_port, pkt=0):
    payload = bytes(pkt)
    metadatas = [
        {
            "value": egress_port,
            "bitwidth": 16
        }
        
    ]

    try:
        controller.switch.PacketOut(payload, metadatas)
        #print(f"--- [Packet-Out] Port {egress_port} BASARILI! ---")
    except Exception as e:
        #print(f"!!! Packet-Out hala basarisiz: {e}")
        pass
...


def write_ipv4_rule(controller, ip_addr, port, mac_addr):
    table_entry = controller.p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (ip_addr, 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "port": port,
            "dstAddr": mac_addr
        })
    controller.switch.WriteTableEntry(table_entry)
...

def write_flow_tracker_rule(controller, flow_id):
    table_entry = controller.p4info_helper.buildTableEntry(
        table_name="MyIngress.flow_tracker",
        match_fields={
            "meta.flow_id": flow_id
        },
        action_name="MyIngress.tracked_flow",
        action_params={}
    )
    controller.switch.WriteTableEntry(table_entry)
...

def update_ip_mac_port_dict(controller, src_ip, src_mac, in_port):
    if src_ip not in controller.ip_mac_port_dict:
        controller.ip_mac_port_dict[src_ip] = {"mac": src_mac, "port": in_port}
        #print(f"--- Veritabani Guncellendi: {src_ip} -> MAC: {src_mac}, Port: {in_port} ---")
    else:
        existing_mac = controller.ip_mac_port_dict[src_ip]["mac"]
        existing_port = controller.ip_mac_port_dict[src_ip]["port"]
        if existing_mac != src_mac or existing_port != in_port:
            controller.ip_mac_port_dict[src_ip] = {"mac": src_mac, "port": in_port}
            #print(f"--- Veritabani Guncellendi: {src_ip} -> MAC: {src_mac}, Port: {in_port} ---")
...


def add_flow_stats_dict(controller, data):
    flow_id = data['flow_id']
    if flow_id not in controller.flow_stats_dict:
        controller.flow_stats_dict[flow_id] = {
            'src_ip': data['src_ip'],
            'dst_ip': data['dst_ip'],
            'proto': data['proto'],
            #'first_seen': data['first_seen'],
            #'last_seen': data['last_seen'],
            #'dur': data['last_seen'] - data['first_seen'],
            #'max_dur': data['last_seen'] - data['first_seen'],
            'is_idle': False,
            'idle_counter': controller.idle_counter
        }
...

def untrack_flow(controller, flow_id):
    if flow_id not in controller.flow_stats_dict:
        return
    controller.switch.DeleteTableEntry(controller.p4info_helper.buildTableEntry(
        table_name="MyIngress.flow_tracker",
        match_fields={
            "meta.flow_id": flow_id
        }
    ))
    del controller.flow_stats_dict[flow_id]
    print(f"--- Flow ID {flow_id} izlemeyi durduruldu ve veriler silindi. ---")
...


def write_to_csv(features_list, colnames):
    df = pd.DataFrame(features_list, columns=colnames)
    is_file_new = os.path.exists("features.csv")
    df.to_csv("features.csv", mode='a', header=not is_file_new, index=False)