/*******************************************************************************
 *  INTEL CONFIDENTIAL
 *
 *  Copyright (c) 2021 Intel Corporation
 *  All Rights Reserved.
 *
 *  This software and the related documents are Intel copyrighted materials,
 *  and your use of them is governed by the express license under which they
 *  were provided to you ("License"). Unless the License provides otherwise,
 *  you may not use, modify, copy, publish, distribute, disclose or transmit
 *  this software or the related documents without Intel's prior written
 *  permission.
 *
 *  This software and the related documents are provided as is, with no express
 *  or implied warranties, other than those that are expressly stated in the
 *  License.
 ******************************************************************************/

 #ifndef _HEADERS_P4
 #define _HEADERS_P4

#include "config.p4"

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    ether_type_t ether_type;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    vlan_id_t vid;
    ether_type_t ether_type;
}

header mpls_h {
    bit<20> label;
    bit<3> exp;
    bit<1> bos;
    bit<8> ttl;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    ip_protocol_t protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    ipv6_addr_t src_addr;
    ipv6_addr_t dst_addr;
}

header tcp_h {
    port_t src_port;
    port_t dst_port;
    seq_num_t seq_no;
    ack_num_t ack_no;
    bit<4> data_offset;
    bit<6> res;
    bit<1> urg;
    bit<1> ack;
    bit<1> psh;
    bit<1> rst;
    bit<1> syn;
    bit<1> fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header tcp_mss_h {
    bit<8> type;
    bit<8> length;
    bit<16> mss_value;
}

header tcp_nop_h {
    bit<8> type;
}

header tcp_end_h {
    bit<8> type;
}

header tcp_sack_permitted_h {
    bit<8> type;
    bit<8> length;
}

header tcp_sack_h {
    bit<8> type;
    bit<8> length;
}

header tcp_sack_data_h {
    bit<32> sle;
    bit<32> rle;
}

header tcp_window_scale_h {
    bit<8> type;
    bit<8> length;
    bit<8> ws;
}

header tcp_timestamp_h {
    bit<8> type;
    bit<8> length;
    bit<32> ts_val;
    bit<32> ts_ecr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header icmp_h {
    bit<8> type_;
    bit<8> code;
    bit<16> hdr_checksum;
}

// Address Resolution Protocol -- RFC 6747
header arp_h {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
    mac_addr_t sender_hw_addr;
    ipv4_addr_t sender_proto_addr;
    mac_addr_t target_hw_addr;
    ipv4_addr_t target_proto_addr;
}

// Segment Routing Extension (SRH) -- IETFv7
header ipv6_srh_h {
    bit<8> next_hdr;
    bit<8> hdr_ext_len;
    bit<8> routing_type;
    bit<8> seg_left;
    bit<8> last_entry;
    bit<8> flags;
    bit<16> tag;
}

// VXLAN -- RFC 7348
header vxlan_h {
    bit<8> flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8> reserved2;
}

// Generic Routing Encapsulation (GRE) -- RFC 1701
header gre_h {
    bit<1> C;
    bit<1> R;
    bit<1> K;
    bit<1> S;
    bit<1> s;
    bit<3> recurse;
    bit<5> flags;
    bit<3> version;
    bit<16> proto;
}

header bridge_h {
    bit<1> syn_respond;
    bit<1> lb_flag;
    bit<1> d_flag;
    bit<1> v_flag;
    bit<1> forward_to_dest;
    bit<1> hit_flag;
    bit<1> cpu_flag;
    bit<1> payload_flag;
    bit<8> index;
}

header tcp_option_h {
    varbit<320> options;
};

@flexible
header psd_header_t {
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
    bit<8> reserved;
    ip_protocol_t protocol;
    bit<16> total_len;
}

struct header_t {
    bridge_h bridged;
    ethernet_h ethernet;
    vlan_tag_h vlan_tag;
    arp_h arp;
    ipv4_h ipv4;
    tcp_h tcp;
    //tcp_option_h tcp_option;
    udp_h udp;
    tcp_mss_h mss;
    tcp_nop_h nop_1;
    tcp_nop_h nop_2;
    tcp_sack_permitted_h sack_permitted;
    tcp_nop_h nop_3;
    tcp_window_scale_h window_scale;
};

@flexible
struct ingress_metadata_t {
    ipv4_addr_t cip;
    port_t cport;
    bit<8> hash_result;
    bit<3>  direction;
};

@flexible
struct egress_metadata_t {
    psd_header_t psd_header;
    bridge_h bridged;
    tcp_option_h tcp_option;
    bit<16> tcp_udp_checksum;
    bit<16> dst_port;
    bit<48> tmp_mac;
    bit<1> is_syn;
};

#endif