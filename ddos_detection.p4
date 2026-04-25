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

register<bit<64>>(65536) flow_packet_max_packet_size;
register<bit<64>>(65536) flow_packet_min_packet_size;
register<bit<64>>(65536) flow_packet_packet_size_sum;



register<bit<64>>(65536) flow_packet_min_iat;
register<bit<64>>(65536) flow_packet_max_iat;
register<bit<64>>(65536) flow_packet_iat_sum;
register<bit<64>>(65536) flow_packet_iat_sum_square;

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
    // action send_to_cpu() {
    //     standard_metadata.egress_spec = CPU_PORT; // CPU portu
    // }

    // action tracked_flow() {
    //     // Bu akış zaten takip ediliyor, hiçbir şey yapma
    // }


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

    // table flow_tracker {
    //     key = {
    //         meta.flow_id : exact; // Symmetric flow_id kullanıyoruz
    //     }
    //     actions = {
    //         tracked_flow; // Hiçbir şey yapma, sadece "hit" olsun
    //         NoAction;     
    //     }
    //     size = 65536;
    //     default_action = NoAction(); 
    // }

   apply {

        // if (standard_metadata.ingress_port == CPU_PORT) { 
        //     standard_metadata.egress_spec = (bit<9>)hdr.packet_out.egress_port;
        //     //hdr.ethernet.srcAddr = hdr.packet_out.dstAddr; // Controller'dan gelen gerçek host MA
        //     return;
        // }

        // if (hdr.arp.isValid()) {
        //     send_to_cpu();
        //     return;
        // }

        if (hdr.ipv4.isValid()) {

            bit<64> fwd_count = 0; bit<64> bwd_count = 0; bit<48> first_seen = 0; bit<48> last_seen = 0;
            //bool is_tracked = false;
            bit<48> current_time = standard_metadata.ingress_global_timestamp;
            bit<1> is_active = 0;
            bit<64> current_packet_size = (bit<64>)standard_metadata.packet_length;
            bit<64> min_packet_size = 0; bit<64> max_packet_size = 0; bit<64> packet_size_sum = 0;
            bit<64> min_iat = 0; bit<64> max_iat = 0; bit<64> iat_sum = 0; bit<64> iat_sum_square = 0;


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

            // if (flow_tracker.apply().miss) {
            //     is_tracked = false;
            //     // Tüm değerleri sıfırla
            //     flow_packet_count_fwd.write(meta.flow_id, 0);
            //     flow_packet_count_bwd.write(meta.flow_id, 0);
            //     flow_packet_first_seen.write(meta.flow_id, 0);
            //     flow_packet_last_seen.write(meta.flow_id, 0);
            //     flow_packet_min_packet_size.write(meta.flow_id, 0);
            //     flow_packet_max_packet_size.write(meta.flow_id, 0);
            //     flow_packet_packet_size_sum.write(meta.flow_id, 0);
            //     flow_packet_min_iat.write(meta.flow_id, 0);
            //     flow_packet_max_iat.write(meta.flow_id, 0);
            //     flow_packet_iat_sum.write(meta.flow_id, 0);
            //     flow_packet_iat_sum_square.write(meta.flow_id, 0);
            //     flow_is_active.write(meta.flow_id, 0);
            // }
            // else {
            //     is_tracked = true;
            // }
            
            
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



            flow_packet_count_fwd.read(fwd_count, meta.flow_id);
            flow_packet_count_bwd.read(bwd_count, meta.flow_id);

            // --- İSTATİSTİK KAYIT ---
            if (hdr.ipv4.srcAddr == meta.first_ip) {
                
                flow_packet_count_fwd.write(meta.flow_id, fwd_count + 1);
            } else {
                
                flow_packet_count_bwd.write(meta.flow_id, bwd_count + 1);
            }

            // --- PAKET BOYUTU İSTATİSTİKLERİ ---
            flow_packet_min_packet_size.read(min_packet_size, meta.flow_id);
            flow_packet_max_packet_size.read(max_packet_size, meta.flow_id);
            flow_packet_packet_size_sum.read(packet_size_sum, meta.flow_id);

            if (current_packet_size < min_packet_size || min_packet_size == 0) {
                flow_packet_min_packet_size.write(meta.flow_id, current_packet_size);
            }
            if (current_packet_size > max_packet_size) {
                flow_packet_max_packet_size.write(meta.flow_id, current_packet_size);
            }
            flow_packet_packet_size_sum.write(meta.flow_id, packet_size_sum + current_packet_size);
            

            // --- IAT İSTATİSTİKLERİ ---

            flow_packet_last_seen.read(last_seen, meta.flow_id);
            if (last_seen == 0) {
                flow_packet_last_seen.write(meta.flow_id, current_time);
                // iat hesaplama yapma, ilk paket olduğu için iat yok
            }
            else {
                bit<48> iat = current_time - last_seen;
                flow_packet_last_seen.write(meta.flow_id, current_time);

                flow_packet_min_iat.read(min_iat, meta.flow_id);
                flow_packet_max_iat.read(max_iat, meta.flow_id);
                flow_packet_iat_sum.read(iat_sum, meta.flow_id);
                flow_packet_iat_sum_square.read(iat_sum_square, meta.flow_id);

                if ((bit<64>)iat < min_iat || min_iat == 0) {
                    flow_packet_min_iat.write(meta.flow_id, (bit<64>)iat);
                }
                if ((bit<64>)iat > max_iat) {
                    flow_packet_max_iat.write(meta.flow_id, (bit<64>)iat);
                }
                flow_packet_iat_sum.write(meta.flow_id, iat_sum + (bit<64>)iat);
                flow_packet_iat_sum_square.write(meta.flow_id, iat_sum_square + ((bit<64>)iat * (bit<64>)iat));   
            }



            flow_packet_iat_sum.read(iat_sum, meta.flow_id);
            flow_packet_iat_sum_square.read(iat_sum_square, meta.flow_id);
            flow_packet_min_iat.read(min_iat, meta.flow_id);
            flow_packet_max_iat.read(max_iat, meta.flow_id);




            if (current_time - first_seen >= WINDOW_TIME) { // 5 saniyeden büyükse
                // digest flow
                meta.stats.flow_id = meta.flow_id;
                meta.stats.fwd_count = fwd_count;
                meta.stats.bwd_count = bwd_count;
                meta.stats.duration = current_time - first_seen;
                meta.stats.packet_size_sum = packet_size_sum + current_packet_size;
                meta.stats.min_packet_size = min_packet_size;
                meta.stats.max_packet_size = max_packet_size;
                meta.stats.iat_sum = iat_sum;
                meta.stats.iat_sum_square = iat_sum_square;
                meta.stats.min_iat = min_iat;
                meta.stats.max_iat = max_iat;
                meta.stats.protocol = hdr.ipv4.protocol;
                digest(388632363, meta.stats); // Controller'a gönder

                //registerları sıfırla
                flow_packet_count_fwd.write(meta.flow_id, 0);
                flow_packet_count_bwd.write(meta.flow_id, 0);
                flow_packet_first_seen.write(meta.flow_id, 0);
                flow_packet_last_seen.write(meta.flow_id, 0);
                flow_packet_min_packet_size.write(meta.flow_id, 0);
                flow_packet_max_packet_size.write(meta.flow_id, 0);
                flow_packet_packet_size_sum.write(meta.flow_id, 0);
                flow_packet_min_iat.write(meta.flow_id, 0);
                flow_packet_max_iat.write(meta.flow_id, 0);
                flow_packet_iat_sum.write(meta.flow_id, 0);
                flow_packet_iat_sum_square.write(meta.flow_id, 0);


                flow_is_active.write(meta.flow_id, 0);
            }
            
            // // Eğer bu akış daha önce kaydedilmemişse (miss)
            // if (is_tracked == false) {
            //     send_to_cpu(); // Paket 64. porta gider
            //     return;        // LPM tablosuna bakma, paketi hemen gönder!
            // }

            // Akış takip ediliyorsa (hit), şimdi yönlendirme yapabiliriz
            ipv4_lpm.apply();
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) { 
    apply {
        // // Eğer paket Controller'a (Port 64) gidiyorsa
        // if (standard_metadata.egress_port== CPU_PORT) { 
        //     hdr.packet_in.setValid(); // Etiketi aktif et
        //     hdr.packet_in.ingress_port = (bit<16>)standard_metadata.ingress_port; // Paketin geldiği portu ekle
        //     hdr.packet_in.flow_id = meta.flow_id; // flow_id bilgisini ekle
        //     flow_packet_count_fwd.read(hdr.packet_in.fwd_count, meta.flow_id);
        //     flow_packet_count_bwd.read(hdr.packet_in.bwd_count, meta.flow_id);
        //     flow_packet_first_seen.read(hdr.packet_in.first_seen, meta.flow_id);
        //     flow_packet_last_seen.read(hdr.packet_in.last_seen, meta.flow_id);
        // }
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