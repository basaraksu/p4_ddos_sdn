/* DDoS Dedektörü - Ana P4 dosyası */

#include <core.p4>
#include <v1model.p4>

#include "p4src/includes/headers.p4"
#include "p4src/includes/parsers.p4"

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { 
    apply { }
}


// Her akışın paket sayısını tutan hafıza (Forward ve Backward için ayrı)
register<bit<32>>(1024) flow_packet_count_fwd; 
register<bit<32>>(1024) flow_packet_count_bwd;

// Her akışın switch'e son geliş zamanını (nanosaniye) tutan hafıza
register<bit<48>>(1024) flow_last_timestamp;

// Her akışın GÖRDÜĞÜ EN BÜYÜK paket arası süreyi (IAT) tutar
register<bit<48>>(1024) flow_iat_max;

// Her akışın TÜM IAT değerlerinin toplamını tutar (Ortalama hesaplamak için)
register<bit<48>>(1024) flow_iat_sum;


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

    apply {
        
        // Eğer paket Controller'dan (CPU_PORT) geldiyse
        if (standard_metadata.ingress_port == 64) { 
            // Paket içindeki egress_port bilgisini fiziksel port olarak ata
            standard_metadata.egress_spec = (bit<9>)hdr.packet_out.egress_port;
            // İşlem bitti, tabloları gezme (isteğe bağlı ama temiz olur)
            return;
        }

        if (hdr.arp.isValid()) {
            // ARP paketlerini doğrudan CPU'ya gönder
            send_to_cpu();
            return;
        }

        // Sadece paket IPv4 ise tabloya bak
        if (hdr.ipv4.isValid()) {

            bit<32> flow_id;
            bit<48> iat;
            bit<48> iat_max = 0;
            bit<48> current_max_iat;
            bit<48> iat_sum = 0;
            bit<48> current_iat_sum;
            bit<48> current_ts;
            bit<48> last_ts;
            bit<32> fwd_count = 0;
            bit<32> bwd_count = 0;
            

            //IP adreslerini sırala (Küçük olan başa)
            bit<32> src_ip = hdr.ipv4.srcAddr;
            bit<32> dst_ip = hdr.ipv4.dstAddr;
            bit<32> first_ip;
            bit<32> second_ip;

            if (src_ip < dst_ip) {
                first_ip = src_ip;
                second_ip = dst_ip;
            } else {
                first_ip = dst_ip;
                second_ip = src_ip;
            }

            // Sıralanmış IP'lere göre Flow ID oluştur
            hash(flow_id, HashAlgorithm.crc16, (bit<32>)0, { first_ip, second_ip }, (bit<32>)1024);


            //Mevcut zamanı al (Nanosaniye cinsinden)
            current_ts = standard_metadata.ingress_global_timestamp;
            

            //Önceki zamanı oku ve farkı hesapla (IAT)
            flow_last_timestamp.read(last_ts, (bit<32>)flow_id);
            
            if (last_ts > 0) { // İlk paket değilse IAT hesapla
                iat = current_ts - last_ts;

                //MAX IAT GÜNCELLEME
                flow_iat_max.read(current_max_iat, (bit<32>)flow_id);
                if (iat > current_max_iat) {
                    flow_iat_max.write((bit<32>)flow_id, iat);
                }

                //SUM IAT GÜNCELLEME (Üzerine ekle)
                flow_iat_sum.read(current_iat_sum, (bit<32>)flow_id);
                flow_iat_sum.write((bit<32>)flow_id, current_iat_sum + iat);

            }

            //Mevcut zamanı bir sonraki paket için kaydet
            flow_last_timestamp.write((bit<32>)flow_id, current_ts);


            // Paket sayısını oku, 1 artır ve geri yaz
            // Yönü tespit et (Küçük IP kaynaksa Fwd, değilse Bwd kabul edelim)
            if (hdr.ipv4.srcAddr == first_ip) {
                // FORWARD TRAFİĞİ
                flow_packet_count_fwd.read(fwd_count, flow_id);
                fwd_count = fwd_count + 1;
                flow_packet_count_fwd.write(flow_id, fwd_count);
            } else {
                // BACKWARD TRAFİĞİ
                flow_packet_count_bwd.read(bwd_count, flow_id);
                bwd_count = bwd_count + 1;
                flow_packet_count_bwd.write(flow_id, bwd_count);
            }

            // MAX IAT ve SUM IAT değerlerini oku
            flow_iat_max.read(iat_max, (bit<32>)flow_id);
            flow_iat_sum.read(iat_sum, (bit<32>)flow_id);

            // Hesaplanan değerleri metadata'ya aktar
            meta.flow_id = flow_id;
            meta.iat_max = iat_max;
            meta.iat_sum = iat_sum;
            meta.fwd_count = fwd_count;
            meta.bwd_count = bwd_count;
            meta.packet_count = fwd_count + bwd_count;

            // Kontrolcüye "Özet" (Digest) gönder
            // if (((fwd_count + bwd_count) & 15) == 0) { // Her 16. pakette bir gönder
            //    digest(1, meta);
            // }

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