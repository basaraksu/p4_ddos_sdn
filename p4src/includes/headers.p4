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

// Kendi özel verilerimizi (feature'ları) tutacağımız yer
struct metadata {
    bit<32> flow_id;
    bit<48> iat_max;
    bit<48> iat_sum;
    bit<32> fwd_count; 
    bit<32> bwd_count; 
    bit<32> packet_count;
}
struct headers{
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
    ethernet_t ethernet;
    ipv4_t ipv4;
    arp_t arp;
}   