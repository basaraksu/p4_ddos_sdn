/* Protokol başlık tanımları (Ethernet, IPv4 vb.) */


// packet out 
@controller_header("packet_out")
header packet_out_header_t {
    bit<16> egress_port;
    bit<32> flow_id;
    bit<32> reason_code; // 0: Normal, 1: Register Request

}

// packet in 
@controller_header("packet_in")
header packet_in_header_t {
    bit<16> ingress_port;
    bit<32> reason_code; // 0: Normal, 1: Register RESPONSE
    bit<32> flow_id;
    bit<48> first_seen;
    bit<48> last_seen;
    bit<64> fwd_count;
    bit<64> bwd_count;
}


header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header arp_t {
    bit<16> htype;   // Hardware type
    bit<16> ptype;   // Protocol type
    bit<8>  hlen;    // Hardware address length
    bit<8>  plen;    // Protocol address length
    bit<16> opcode;  // 1: Request, 2: Reply
    bit<48> srcMac;  // Gönderen MAC
    bit<32> srcIp;   // Gönderen IP
    bit<48> dstMac;  // Hedef MAC
    bit<32> dstIp;   // Hedef IP
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct flow_features_t {
    bit<32> flow_id;
    bit<32> first_ip;
    bit<32> second_ip;
    bit<16> src_port;
    bit<16> dst_port;
    bit<8> protocol;
    bit<64> fwd_count;
    bit<64> bwd_count;
    bit<64> packet_size_sum;
    bit<64> duration;
}

struct metadata {
    flow_features_t stats; 
    bit<32> flow_id;
    bit<32> first_ip;
    bit<32> second_ip;
    bit<16> src_port;
    bit<16> dst_port;
    bit<8> protocol;
}
struct headers{
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
    ethernet_t ethernet;
    ipv4_t ipv4;
    arp_t arp;
    tcp_t tcp;
    udp_t udp;
}   