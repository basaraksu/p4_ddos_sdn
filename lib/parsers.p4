/* Paket Ayrıştırma Mantığı */

parser MyParser(packet_in packet, out headers hdr, 
                inout metadata meta, inout standard_metadata_t standard_meta){

    state start {
        transition select(standard_meta.ingress_port) {
            64: parse_packet_out; // Controller'dan gelen paketler
            default: parse_ethernet; // Diğer tüm paketler
        }
    }    

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet; // Controller'dan gelen paketlerde ethernet header'ını da ayrıştır
    }            

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4; // IPv4
            0x0806: parse_arp;  // ARP
            default: accept;
        
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }    

    

}