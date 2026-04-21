/* DDoS Dedektörü - Ana P4 dosyası */

#include <core.p4>
#include <v1model.p4>

#include "p4src/includes/headers.p4"
#include "p4src/includes/parsers.p4"

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } } 


// Her akışın paket sayısını tutan hafıza (Forward ve Backward için ayrı)
register<bit<64>>(65536) flow_packet_count_fwd; 
register<bit<64>>(65536) flow_packet_count_bwd;

// Akış başına ortalama paket başlığı uzunluğunu tutan hafıza (Forward ve Backward için ayrı)
// register<bit<64>>(65536) flow_fwd_bytes;
// register<bit<64>>(65536) flow_bwd_bytes;

register<bit<48>>(65536) flow_packet_first_seen;
register<bit<48>>(65536) flow_packet_last_seen;


control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    
    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        // 1. Hedef portu belirle
        standard_metadata.egress_spec = port;
        
        // 2. Ethernet başlığını güncelle 
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr; // Eski hedef, yeni kaynak (Switch MAC)
        hdr.ethernet.dstAddr = dstAddr;              // Controller'dan gelen gerçek host MAC'i
        
        // 3. TTL düşür
        // hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action send_to_cpu() {
        standard_metadata.egress_spec = 64; // CPU portu
    }

    action tracked_flow() {
        // Bu akış zaten takip ediliyor, hiçbir şey yapma
    }


    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm; // Longest Prefix Match (En uzun eşleşme)
        }
        actions = {
            ipv4_forward;
            send_to_cpu;
            NoAction;
        }
        size = 1024;
        default_action = send_to_cpu(); // Bilinmeyen paketleri CPU'ya gönder
    }

    table flow_tracker {
        key = {
            meta.flow_id : exact; // Symmetric flow_id kullanıyoruz
        }
        actions = {
            tracked_flow; // Hiçbir şey yapma, sadece "hit" olsun
            NoAction;     
        }
        size = 65536;
        default_action = NoAction(); 
    }

   apply {

        if (standard_metadata.ingress_port == 64) { 
            if (hdr.packet_out.reason_code == 1) { // Register Request
                send_to_cpu();
                return;
            }
            standard_metadata.egress_spec = (bit<9>)hdr.packet_out.egress_port;
            return;
        }

        if (hdr.arp.isValid()) {
            send_to_cpu();
            return;
        }

        if (hdr.ipv4.isValid()) {

            bit<64> fwd_count = 0; bit<64> bwd_count = 0; bit<48> first_seen = 0; //bit<48> last_seen = 0;
            bool is_tracked = false;

            // --- PORT ÇEKME MANTIĞI ---
            if (hdr.tcp.isValid()) {
                meta.src_port = hdr.tcp.srcPort; meta.dst_port = hdr.tcp.dstPort;
            } else if (hdr.udp.isValid()) {
                meta.src_port = hdr.udp.srcPort; meta.dst_port = hdr.udp.dstPort;
            } else {
                meta.src_port = 0; meta.dst_port = 0; // ICMP vb. için portları sıfırla
            }

            // --- SYMMETRIC KEY SIRALAMA ---
            if (hdr.ipv4.srcAddr < hdr.ipv4.dstAddr) {
                meta.first_ip = hdr.ipv4.srcAddr; meta.second_ip = hdr.ipv4.dstAddr;
            } else {
                meta.first_ip = hdr.ipv4.dstAddr; meta.second_ip = hdr.ipv4.srcAddr;
            }

            // --- HASH ---
            hash(meta.flow_id, HashAlgorithm.crc16, (bit<32>)0, 
                { meta.first_ip, meta.second_ip, hdr.ipv4.protocol }, 
                (bit<32>)65536);

            if (flow_tracker.apply().miss) {
                is_tracked = false;
                // Tüm değerleri sıfırla
                flow_packet_count_fwd.write(meta.flow_id, 0);
                flow_packet_count_bwd.write(meta.flow_id, 0);
                // flow_fwd_bytes.write(meta.flow_id, 0);
                // flow_bwd_bytes.write(meta.flow_id, 0);
                flow_packet_first_seen.write(meta.flow_id, 0);
                flow_packet_last_seen.write(meta.flow_id, 0);
            }
            else {
                is_tracked = true;
            }


            // --- İSTATİSTİK KAYIT ---
            if (hdr.ipv4.srcAddr == meta.first_ip) {
                flow_packet_count_fwd.read(fwd_count, meta.flow_id);
                flow_packet_count_fwd.write(meta.flow_id, fwd_count + 1);
                
                // flow_fwd_bytes.read(fwd_bytes, meta.flow_id);
                // flow_fwd_bytes.write(meta.flow_id, fwd_bytes + (bit<64>)hdr.ipv4.totalLen);
            } else {
                flow_packet_count_bwd.read(bwd_count, meta.flow_id);
                flow_packet_count_bwd.write(meta.flow_id, bwd_count + 1);

                // flow_bwd_bytes.read(bwd_bytes, meta.flow_id);
                // flow_bwd_bytes.write(meta.flow_id, bwd_bytes + (bit<64>)hdr.ipv4.totalLen); 
            }
            
            flow_packet_first_seen.read(first_seen, meta.flow_id);
            if (first_seen == 0) {
                flow_packet_first_seen.write(meta.flow_id, standard_metadata.ingress_global_timestamp);
            }


            flow_packet_last_seen.write(meta.flow_id, standard_metadata.ingress_global_timestamp);
            
            // Eğer bu akış daha önce kaydedilmemişse (miss)
            if (is_tracked == false) {
                send_to_cpu(); // Paket 64. porta gider
                return;        // LPM tablosuna bakma, paketi hemen gönder!
            }

            // Akış takip ediliyorsa (hit), şimdi yönlendirme yapabiliriz
            ipv4_lpm.apply();
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) { 
    apply {
        // Eğer paket Controller'a (Port 64) gidiyorsa
        if (standard_metadata.egress_port== 64) { 
            hdr.packet_in.setValid(); // Etiketi aktif et
            hdr.packet_in.ingress_port = (bit<16>)standard_metadata.ingress_port; // Geldiği portu içine yaz
            if (hdr.packet_out.isValid() && hdr.packet_out.reason_code == 1) { //register sorgulama
            hdr.packet_in.flow_id = hdr.packet_out.flow_id; // Akış ID'sini içine yaz
            hdr.packet_in.reason_code = hdr.packet_out.reason_code; // Register request olduğunu belirt
            flow_packet_count_fwd.read(hdr.packet_in.fwd_count, hdr.packet_in.flow_id); 
            flow_packet_count_bwd.read(hdr.packet_in.bwd_count, hdr.packet_in.flow_id);
            flow_packet_first_seen.read(hdr.packet_in.first_seen, hdr.packet_in.flow_id);
            flow_packet_first_seen.write(hdr.packet_in.flow_id, 0); // Controller'a gönderildikten sonra sıfırla
        } else {    
            hdr.packet_in.flow_id = meta.flow_id; // Akış ID'sini içine yaz
            hdr.packet_in.reason_code = 0; // Normal Packet-In olduğunu belirt
            flow_packet_first_seen.read(hdr.packet_in.first_seen, meta.flow_id);
        }
        
        flow_packet_last_seen.read(hdr.packet_in.last_seen, hdr.packet_in.flow_id);
        }
    } 
}


control MyComputeChecksum(inout headers hdr, inout metadata meta) { apply { } }

control MyDeparser(packet_out packet, in headers hdr) {
        apply {
        packet.emit(hdr.packet_in); // Controller'a giden paketlerde packet_in header'ını ekle
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);  
        packet.emit(hdr.ipv4);
    }
    
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;