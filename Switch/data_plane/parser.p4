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

#ifndef _PARSER_P4
#define _PARSER_P4

#include "headers.p4"

parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser TofinoEgressParser(
        packet_in pkt,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

parser SwitchIngressParser(packet_in pkt,
        out header_t hdr,
        out ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    TofinoIngressParser() tofino_ingress_parser;

    state start {
        tofino_ingress_parser.apply(pkt, ig_intr_md);
        transition parse_md;
    }

    state parse_md {
        hdr.bridged.setValid();
        hdr.bridged.syn_respond = 1w0;
        hdr.bridged.lb_flag = 1w0;
        hdr.bridged.d_flag = 1w0;
        hdr.bridged.v_flag = 1w0;
        hdr.bridged.forward_to_dest = 1w0;
        hdr.bridged.hit_flag = 1w0;
        hdr.bridged.cpu_flag = 1w0;
        hdr.bridged.payload_flag = 1w1;
        hdr.bridged.index = 0;
        ig_md.cip = 0;
        ig_md.cport = 0;
        ig_md.hash_result = 0;
        ig_md.direction = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_VLAN : parse_vlan;
            default : accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_vlan {
        pkt.extract(hdr.vlan_tag);
        transition select (hdr.vlan_tag.ether_type) {
            ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol, hdr.ipv4.frag_offset) {
            (IP_PROTOCOLS_TCP, 0)  : parse_tcp;
            (IP_PROTOCOLS_UDP, 0)  : parse_udp;
            // Do NOT parse the next header if IP packet is fragmented.
            default                : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        // transition select(hdr.tcp.flags) {
        //     (0b00000010): parse_tcp_options;
        //     default: accept;
        // }
        transition accept;
    }

    // state parse_tcp_options {
    //     pkt.extract(
    //         hdr.tcp_option,
    //         (((bit<32>)hdr.tcp.data_offset - 5) * 32w32 + 32)
    //     );
    //     transition accept;
    // }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

parser SwitchEgressParser(packet_in pkt,
        out header_t hdr,
        out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    Checksum() ipv4_checksum;
    Checksum() tcp_checksum;
    Checksum() udp_checksum;

    TofinoEgressParser() tofino_egress_parser;

    state start {
        tofino_egress_parser.apply(pkt, eg_intr_md);
        transition parse_bridged;
    }

    state parse_bridged {
        eg_md.bridged.setValid();
        pkt.extract(eg_md.bridged);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_VLAN : parse_vlan;
            default : reject;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_vlan {
        pkt.extract(hdr.vlan_tag);
        transition select (hdr.vlan_tag.ether_type) {
            ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        ipv4_checksum.add(hdr.ipv4);
        tcp_checksum.subtract({hdr.ipv4.src_addr,hdr.ipv4.dst_addr});
        udp_checksum.subtract({hdr.ipv4.src_addr,hdr.ipv4.dst_addr});
        transition select(hdr.ipv4.protocol, hdr.ipv4.frag_offset) {
            (IP_PROTOCOLS_TCP, 0)  : parse_tcp;
            (IP_PROTOCOLS_UDP, 0)  : parse_udp;
            // Do NOT parse the next header if IP packet is fragmented.
            default                : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        tcp_checksum.subtract_all_and_deposit(eg_md.tcp_udp_checksum);
        tcp_checksum.subtract({hdr.tcp.checksum});
        tcp_checksum.subtract({hdr.tcp.src_port, hdr.tcp.dst_port});
        transition select(eg_md.bridged.syn_respond) {
            1w1: parse_tcp_options;
            default: accept;
        }
    }
    
    state parse_tcp_options {
        pkt.advance(160);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

#endif