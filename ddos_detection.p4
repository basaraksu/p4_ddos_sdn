/* DDoS Dedektörü - Ana P4 dosyası */

#include <core.p4>
#include <v1model.p4>

#include "p4src/includes/headers.p4"
#include "p4src/includes/parsers.p4"

const bit<48> WINDOW_TIME = 5_000_000; // 5 saniye (nanosecond cinsinden)

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } } 


// Her akışın paket sayısını tutan hafıza (Forward ve Backward için ayrı)
register<bit<64>>(65536) flow_packet_count_fwd; 
register<bit<64>>(65536) flow_packet_count_bwd;


register<bit<48>>(65536) flow_packet_first_seen;
register<bit<48>>(65536) flow_packet_last_seen;

// register<bit<64>>(65536) flow_packet_max_packet_size;
// register<bit<64>>(65536) flow_packet_min_packet_size;
register<bit<64>>(65536) flow_packet_packet_size_sum;



// register<bit<64>>(65536) flow_packet_min_iat;
// register<bit<64>>(65536) flow_packet_max_iat;
// register<bit<64>>(65536) flow_packet_iat_sum;
// register<bit<64>>(65536) flow_packet_iat_sum_square;

register<bit<1>>(65536) flow_is_active;


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

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm; // Longest Prefix Match (En uzun eşleşme)
        }
        actions = {
            ipv4_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

   apply {

        if (hdr.ipv4.isValid()) {

            bit<64> fwd_count = 0; bit<64> bwd_count = 0; bit<48> first_seen = 0; // bit<48> last_seen = 0;
            bit<48> current_time = standard_metadata.ingress_global_timestamp;
            bit<1> is_active = 0;
            bit<64> current_packet_size = (bit<64>)standard_metadata.packet_length;
            bit<64> packet_size_sum = 0;
    

             // --- PORT ÇEKME MANTIĞI ---
            if (hdr.tcp.isValid()) {
                meta.src_port = hdr.tcp.srcPort; meta.dst_port = hdr.tcp.dstPort;
            } else if (hdr.udp.isValid()) {
                meta.src_port = hdr.udp.srcPort; meta.dst_port = hdr.udp.dstPort;
            }  else {
                meta.src_port = 0; meta.dst_port = 0; // ICMP vb. için portları sıfırla
            }


            // --- SYMMETRIC KEY SIRALAMA ---
            if (hdr.ipv4.srcAddr < hdr.ipv4.dstAddr) {
                meta.first_ip = hdr.ipv4.srcAddr; meta.second_ip = hdr.ipv4.dstAddr;
            } else {
                meta.first_ip = hdr.ipv4.dstAddr; meta.second_ip = hdr.ipv4.srcAddr;
            }

            // --- FLOW ID HESAPLAMA ---

            hash(meta.flow_id, HashAlgorithm.crc16, (bit<32>)0, 
                { 
                    meta.first_ip, 
                    meta.second_ip, 
                    meta.src_port, 
                    meta.dst_port, 
                    hdr.ipv4.protocol 
                }, 
                (bit<32>)65536);
            


            // Window aktif değilse first_seen'i güncelle, aktifse first_seen'i oku
            flow_is_active.read(is_active, meta.flow_id);
            if (is_active == 0) { // Windowdaki ilk paket
                flow_is_active.write(meta.flow_id, 1);
                first_seen = standard_metadata.ingress_global_timestamp;
                flow_packet_first_seen.write(meta.flow_id, first_seen);  
            }
            else {
                flow_packet_first_seen.read(first_seen, meta.flow_id);
            }



            
            

            // --- İSTATİSTİK KAYIT ---
            if (hdr.ipv4.srcAddr == meta.first_ip) {
                flow_packet_count_fwd.read(fwd_count, meta.flow_id);
                flow_packet_count_fwd.write(meta.flow_id, fwd_count + 1);
            } else {
                flow_packet_count_bwd.read(bwd_count, meta.flow_id);
                flow_packet_count_bwd.write(meta.flow_id, bwd_count + 1);
            }

            // // --- PAKET BOYUTU İSTATİSTİKLERİ ---
            
            flow_packet_packet_size_sum.read(packet_size_sum, meta.flow_id);

            
            flow_packet_packet_size_sum.write(meta.flow_id, packet_size_sum + current_packet_size);
            


            




            if (current_time - first_seen >= WINDOW_TIME) { // 5 saniyeden büyükse
            
                flow_packet_count_fwd.read(fwd_count, meta.flow_id);
                flow_packet_count_bwd.read(bwd_count, meta.flow_id);
                // digest flow
                meta.stats.flow_id = meta.flow_id;
                meta.stats.first_ip = meta.first_ip;
                meta.stats.second_ip = meta.second_ip;
                meta.stats.src_port = meta.src_port;
                meta.stats.dst_port = meta.dst_port;
                meta.stats.protocol = hdr.ipv4.protocol;
                meta.stats.fwd_count = fwd_count;
                meta.stats.bwd_count = bwd_count;
                meta.stats.packet_size_sum = packet_size_sum + current_packet_size;
                meta.stats.duration = (bit<64>)(current_time - first_seen);
                digest(388632363, meta.stats); // Controller'a gönder

                //registerları sıfırla
                flow_packet_count_fwd.write(meta.flow_id, 0);
                flow_packet_count_bwd.write(meta.flow_id, 0);
                flow_packet_first_seen.write(meta.flow_id, 0);
                flow_packet_last_seen.write(meta.flow_id, 0);
                flow_packet_packet_size_sum.write(meta.flow_id, 0);
                


                flow_is_active.write(meta.flow_id, 0);
            }

            // Akış takip ediliyorsa (hit), şimdi yönlendirme yapabiliriz
            ipv4_lpm.apply();
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) { 
    apply {
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