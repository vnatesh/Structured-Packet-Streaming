/* -*- P4_16 -*- */

/*
 * P4 tuple filter
 *
 * The switch receives a packet, filters the packet on 'age' colmumn, applies a project operation,
    and sends packet to destination host
 *
 * If an unknown operation is specified or the header is not valid, the packet
 * is dropped 
 */

#include <core.p4>
#include <v1model.p4>


const bit<16> TYPE_IPV4 = 0x800;
const bit<8> IP_PROT_UDP = 0x11;
const bit<16> DPORT = 0x0da2;
const bit<32> MY_AGE = 0x0000001b; // 27
const bit<80> MY_NAME = 0x76696B61730000000000; 


typedef bit<9>  egressSpec_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> macAddr_t;

/*
 * Standard ethernet header 
 */
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}


/*
 * Standard ipv4 header 
 */
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}


/*
 * Standard tcp header 
 */
// header tcp_t {
//     bit<16> srcPort;
//     bit<16> dstPort;
//     bit<32> seqNo;
//     bit<32> ackNo;
//     bit<4>  dataOffset;
//     bit<3>  res;
//     bit<3>  ecn;
//     bit<6>  ctrl;
//     bit<16> window;
//     bit<16> checksum;
//     bit<16> urgentPtr;
// }


/*
 * Standard udp header 
 */
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

/*
 * This is a custom protocol header for the filter. We'll use 
 * ethertype 0x1234
 */
header age_t {
    bit<32> val;
}

header height_t {
    bit<32> val;
}

header weight_t {
    bit<32> val;
}

header name_t {
    bit<80> val;
}


struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    udp_t       udp;
    age_t       age;
    height_t    height;
    weight_t    weight;
    name_t      name;
}

 
struct metadata {
    /* In our case it is empty */
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {


    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4    : parse_ipv4;
            default      : accept;
        }
    }
        
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROT_UDP : parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            DPORT   :   parse_age;
            default :   accept;
        }
    }

    state parse_age {
        packet.extract(hdr.age);
        transition parse_height;
    }

    state parse_height {
        packet.extract(hdr.height);
        transition parse_weight;
    }

    state parse_weight {
        packet.extract(hdr.weight);
        transition parse_name;
    }

    state parse_name {
        packet.extract(hdr.name);
        transition accept;
    }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/
control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply { }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action drop() {
        mark_to_drop();
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
            

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
    }
        size = 1024;
        default_action = drop();
    }

    apply {
        if(hdr.age.isValid() && hdr.height.isValid() && 
            hdr.weight.isValid() && hdr.name.isValid() && hdr.ipv4.isValid()) {
            if(hdr.age.val <= MY_AGE && hdr.name.val == MY_NAME) {
                ipv4_lpm.apply();
            } else {
                drop();
            }

        } else if(hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        } else {
            drop();
        }
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
   
    apply { 
       
    }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
    update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

    // update_checksum(hdr.tcp.isValid(), { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, meta.meta.tcpLength, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.tcp.seqNo, hdr.tcp.ackNo, hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgentPtr }, hdr.tcp.checksum, HashAlgorithm.csum16);
    // update_checksum_with_payload(
    //     hdr.tcp.isValid(), 
    //         { hdr.ipv4.srcAddr, 
    //         hdr.ipv4.dstAddr, 
    //         8w0, 
    //         hdr.ipv4.protocol, 
    //         meta.meta.tcpLength, 
    //         hdr.tcp.srcPort, 
    //         hdr.tcp.dstPort, 
    //         hdr.tcp.seqNo, 
    //         hdr.tcp.ackNo, 
    //         hdr.tcp.dataOffset, 
    //         hdr.tcp.res, 
    //         hdr.tcp.flags, 
    //         hdr.tcp.window, 
    //         hdr.tcp.urgentPtr }, 
    //         hdr.tcp.checksum, 
    //         HashAlgorithm.csum16);

    // update_checksum(
    //     hdr.udp.isValid(),
    //         { hdr.udp.srcPort,
    //         hdr.udp.dstPort,
    //         hdr.udp.length_,
    //         hdr.ipv4.srcAddr,
    //         hdr.ipv4.dstAddr,
    //         hdr.tupleVal.age,
    //         hdr.tupleVal.height,
    //         hdr.tupleVal.weight,
    //         hdr.tupleVal.name},
    //         hdr.udp.checksum,
    //         HashAlgorithm.csum16);

    }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.age);
        packet.emit(hdr.height);
        packet.emit(hdr.weight);
        packet.emit(hdr.name);
    }
}

/*************************************************************************
 ***********************  S W I T T C H **********************************
 *************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

