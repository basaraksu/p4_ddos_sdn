/* Protokol başlık tanımları (Ethernet, IPv4 vb.) */


// packet out 
@controller_header("packet_out")
header packet_out_header_t {
    bit<16> egress_port;
    //bit<16> mcast_grp;
}

// packet in 
@controller_header("packet_in")
header packet_in_header_t {
    bit<16>  ingress_port;
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

struct flow_features_t {
    bit<32> flow_id;
    bit<48> iat_max;
    bit<48> iat_sum;
    bit<32> fwd_count;
    bit<32> bwd_count;
    bit<32> packet_count;
    bit<48> duration;
    bit<32> fwd_header_len;
    bit<32> bwd_header_len;
    bit<48> bwd_iat_tot;
    bit<48> fwd_iat_min;
}

struct metadata {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> first_ip;
    bit<32> second_ip;
    bit<32> flow_id;
    flow_features_t stats; // 'learn' yerine 'stats' dedik
}
struct headers{
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
    ethernet_t ethernet;
    ipv4_t ipv4;
    arp_t arp;
}   