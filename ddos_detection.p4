/* DDoS Dedektörü - Ana P4 dosyası */

#include <core.p4>
#include <v1model.p4>

#include "p4src/includes/headers.p4"
#include "p4src/includes/parsers.p4"

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } } 


// Her akışın paket sayısını tutan hafıza (Forward ve Backward için ayrı)
register<bit<32>>(1024) flow_packet_count_fwd; 
register<bit<32>>(1024) flow_packet_count_bwd;

// Her akışın switch'e son geliş zamanını (nanosaniye) tutan hafıza
register<bit<48>>(1024) flow_last_timestamp;

// Her akışın GÖRDÜĞÜ EN BÜYÜK paket arası süreyi (IAT) tutar
register<bit<48>>(1024) flow_iat_max;

// Her akışın TÜM IAT değerlerinin toplamını tutar (Ortalama hesaplamak için)
register<bit<48>>(1024) flow_iat_sum;

// Her akışın başlangıç zamanını tutar (Flow Duration hesaplamak için)
register<bit<48>>(1024) flow_start_timestamp;

// Akış başına ortalama paket başlığı uzunluğunu tutan hafıza (Forward ve Backward için ayrı)
register<bit<32>>(1024) flow_fwd_header_len;
register<bit<32>>(1024) flow_bwd_header_len;

// Bwd IAT toplamını tutan hafıza 
register<bit<48>>(1024) flow_bwd_iat_sum;
register<bit<48>>(1024) flow_bwd_last_ts; // Sadece dönüş paketlerinin son geliş zamanı


// Fwd IAT minimumunu tutan hafıza
register<bit<48>>(1024) flow_fwd_iat_min;
register<bit<48>>(1024) flow_fwd_last_ts;

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
            bit<48> start_ts;
            bit<48> current_ts;
            bit<48> last_ts;
            bit<32> fwd_count = 0;
            bit<32> bwd_count = 0;
            bit<32> total_count = 0;
            bit<32> current_h_len = 0;
            bit<32> fwd_header_len = 0;
            bit<32> bwd_header_len = 0;
            bit<48> b_last_ts = 0;
            bit<48> b_iat = 0;
            bit<48> b_sum = 0;
            bit<48> f_last_ts = 0;
            bit<48> f_iat = 0;
            bit<48> f_min = 0;
            
            bit<32> src_ip = hdr.ipv4.srcAddr;
            bit<32> dst_ip = hdr.ipv4.dstAddr;
            bit<32> first_ip;
            bit<32> second_ip;
            
            //IP adreslerini sırala (Küçük olan başa)
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

            flow_start_timestamp.read(start_ts, flow_id);
            if (start_ts == 0) { // Eğer bu akışın ilk paketiyse
                flow_start_timestamp.write(flow_id, current_ts);
                start_ts = current_ts;
            }
            
            



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
                flow_packet_count_fwd.read(fwd_count, flow_id);
                fwd_count = fwd_count + 1;
                flow_packet_count_fwd.write(flow_id, fwd_count);
            } else {
                flow_packet_count_bwd.read(bwd_count, flow_id);
                bwd_count = bwd_count + 1;
                flow_packet_count_bwd.write(flow_id, bwd_count);
            }
            

            current_h_len = (bit<32>)hdr.ipv4.ihl * 4; // IHL değeri 32-bit kelime cinsindendir, byte'a çevirmek için 4 ile çarpıyoruz
            
            // Akış başına ortalama paket başlığı uzunluğunu güncelle
            if (hdr.ipv4.srcAddr == first_ip) {
                flow_fwd_header_len.read(fwd_header_len, flow_id);
                flow_fwd_header_len.write(flow_id, fwd_header_len + current_h_len);
            } else {
                flow_bwd_header_len.read(bwd_header_len, flow_id);
                flow_bwd_header_len.write(flow_id, bwd_header_len + current_h_len);
            }


            flow_packet_count_fwd.read(fwd_count, flow_id);
            flow_packet_count_bwd.read(bwd_count, flow_id);
            total_count = fwd_count + bwd_count;


            if (hdr.ipv4.srcAddr == second_ip) {
                flow_bwd_last_ts.read(b_last_ts, flow_id);
                if (b_last_ts > 0) {
                    b_iat = current_ts - b_last_ts;
                    flow_bwd_iat_sum.read(b_sum, flow_id);
                    flow_bwd_iat_sum.write(flow_id, b_sum + b_iat);
                }
                flow_bwd_last_ts.write(flow_id, current_ts);
            } else {
                flow_fwd_last_ts.read(f_last_ts, flow_id);
                if (f_last_ts > 0) {
                    f_iat = current_ts - f_last_ts;
                    flow_fwd_iat_min.read(f_min, flow_id);
                    if (f_iat < f_min || f_min == 0) {
                        flow_fwd_iat_min.write(flow_id, f_iat);
                    }
                }
                flow_fwd_last_ts.write(flow_id, current_ts);
            }



            // Kontrolcüye "Özet" (Digest) gönder
            if (total_count > 0 && (total_count & 15) == 0) { // Her 16. pakette bir gönder
               
                // MAX IAT ve SUM IAT değerlerini oku
                flow_iat_max.read(iat_max, (bit<32>)flow_id);
                flow_iat_sum.read(iat_sum, (bit<32>)flow_id);

                // Ortalama paket başlığı uzunluğunu oku
                flow_fwd_header_len.read(fwd_header_len, flow_id);
                flow_bwd_header_len.read(bwd_header_len, flow_id);

                // Bwd IAT toplamını oku
                flow_bwd_iat_sum.read(b_sum, flow_id);

                // Fwd IAT minimumunu oku
                flow_fwd_iat_min.read(f_min, flow_id);

                // Hesaplanan değerleri metadata'ya aktar
                meta.stats.flow_id = flow_id;
                meta.stats.iat_max = iat_max;
                meta.stats.iat_sum = iat_sum;
                meta.stats.fwd_count = fwd_count;
                meta.stats.bwd_count = bwd_count;
                meta.stats.packet_count = total_count;
                meta.stats.duration = current_ts - start_ts; 
                meta.stats.fwd_header_len = fwd_header_len;
                meta.stats.bwd_header_len = bwd_header_len;
                meta.stats.bwd_iat_tot = b_sum;
                meta.stats.fwd_iat_min = f_min;
               
               
               
               digest(388632363, meta.stats); // "1" burada digest ID'si, istediğiniz gibi tanımlayabilirsiniz
            }

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