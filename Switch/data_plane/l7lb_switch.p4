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

#ifndef _MAIN_P4
#define _MAIN_P4


#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif
#include "parser.p4"
#include "deparser.p4"

control SwitchIngress(inout header_t hdr,
        inout ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md){
    Hash<bit<8>>(HashAlgorithm_t.CRC8) lb_index_hasher;
    Alpm(number_partitions = 1024, subtrees_per_partition = 2) algo_lpm;
    action drop() {
        ig_intr_dprsr_md.drop_ctl = 0x1;
    }

    action nop() {

    }

    action reply_arp(mac_addr_t arp_mac) {
        hdr.ethernet.dst_addr = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr = arp_mac;
        hdr.arp.opcode = 2;
        hdr.arp.sender_hw_addr = arp_mac;
        hdr.arp.sender_proto_addr = hdr.arp.target_proto_addr;
        hdr.arp.target_hw_addr = hdr.ethernet.src_addr;
        hdr.arp.target_proto_addr = hdr.arp.sender_proto_addr;
        ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }

    table arp_table{
        key = {
            hdr.arp.opcode: exact;
            hdr.arp.target_proto_addr: exact;
        }
        actions = {
            reply_arp;
            drop;
        }
        const default_action = drop;
        size = 1024;
    }

    action vip_hit() {
        ig_md.direction = 0b001;
        ig_md.cip = hdr.ipv4.src_addr;
        ig_md.cport = hdr.tcp.src_port;
    }

    action switch_hit() {
        ig_md.direction =  0b100;
    }

    table vip_lookup_table {
        key = {
            hdr.ipv4.dst_addr: exact;
            hdr.tcp.dst_port: exact;
        }
        actions = {
            vip_hit;
            switch_hit;
            nop;
        }
        const default_action = nop;
        const entries = {
            (VIRTUAL_IP, VIRTUAL_PORT) : vip_hit();
            (SWITCH_IP, SWITCH_PORT)   : switch_hit();
        }
        size = 2;  
    }

    action dip_hit() {
        ig_md.direction = 0b010;
        ig_md.cip = hdr.ipv4.dst_addr;
        ig_md.cport = hdr.tcp.dst_port;
    }
    
    table dip_lookup_table {
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.tcp.src_port: exact;
        }
        actions = {
            dip_hit;
            nop;
        }
        const default_action = nop;
        size = DIP_TABLE_SIZE;
    }

    action calculate_crc8() {
        ig_md.hash_result = lb_index_hasher.get({ig_md.cip, ig_md.cport});
    }

    table calculate_crc8_table {
        actions = {
            calculate_crc8;
        }
        const default_action = calculate_crc8;
        size = 1;
    }
    action no_payload() {
        hdr.bridged.payload_flag = 1w0;
    }

    table calculate_payload_table {
        key = {
            hdr.ipv4.total_len: exact;
            hdr.tcp.data_offset: exact;
        }
        actions = {
            nop;
            no_payload;
        }
        const entries = {
            (40, 5):  no_payload;
            (44, 6):  no_payload;
            (48, 7):  no_payload;
            (52, 8):  no_payload;
            (56, 9):  no_payload;
            (60, 10): no_payload;
            (64, 11): no_payload;
            (68, 12): no_payload;
            (72, 13): no_payload;
            (76, 14): no_payload;
            (80, 15): no_payload;
        }
        const default_action = nop;
        size = 16;
    }

    // action respond_syn() {
    //     ig_md.skip_oft_flag = 1w1;
    //     ig_md.skip_forward_flag = 1w1;
    //     hdr.bridged.syn_respond = 1w1;
    //     hdr.ethernet.dst_addr = hdr.ethernet.src_addr;
    //     hdr.ethernet.src_addr = 0xabababcdcdcd;
    //     ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    // }

    // action skip_oft_and_forward_to_lb() {
    //     ig_md.skip_oft_flag = 1w1;
    //     hdr.bridged.index = ig_md.hash_result;
    //     hdr.bridged.lb_flag = 1w1;
    // }

    // action skip_oft() {
    //     ig_md.skip_oft_flag = 1w1;
    //     hdr.bridged.forward_to_dest = 1w1;
    // }

    // action forward_to_dest() {
    //     hdr.bridged.forward_to_dest = 1w1;
    //     hdr.bridged.v_flag = 1w1;
    // }

    // action send_to_cpu() {
    //     ig_intr_tm_md.ucast_egress_port = 192;
    //     ig_md.skip_oft_flag = 1w1;
    // }

    // table preprocess_table {
    //     key = {
    //         hdr.tcp.flags: ternary;
    //         ig_md.direction: ternary;
    //         ig_md.payload_flag: ternary;
    //     }
    //     actions = {
    //         respond_syn;
    //         skip_oft_and_forward_to_lb;
    //         skip_oft;
    //         forward_to_dest;
    //         send_to_cpu;
    //         nop;
    //     }
    //     const entries = {
    //         (0b00000010, 3w1, 1w0): respond_syn();
    //         (0b00000001, _, _): skip_oft_and_forward_to_lb();
    //         (0b00000100, _, _): skip_oft_and_forward_to_lb();
    //         (_, 3w1, 1w1): skip_oft_and_forward_to_lb();
    //         (_, 3w2, _): forward_to_dest();
    //         (_, 3w4, _): send_to_cpu();
    //         (_, 3w0, _): skip_oft();
    //     }
    //     const default_action = nop;
    //     size = 7;
    // }

    action oft_hit(bit<8> d_index) {
        hdr.bridged.index = d_index;
        hdr.bridged.hit_flag = 1w1;
    }

    table offload_connection_table {
        key = {
            ig_md.cip: exact;
            ig_md.cport: exact;
        }
        actions = {
            oft_hit;
            nop;
        }
        const default_action = nop;
        size = 143360;
    }
    
    action set_egress_port(mac_addr_t src_mac, mac_addr_t dst_mac, PortId_t dst_port) {
        hdr.ethernet.src_addr = src_mac;
        hdr.ethernet.dst_addr = dst_mac;
        ig_intr_tm_md.ucast_egress_port = dst_port;
    }
    
    table dest_to_egress_port_table {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }

        actions = {
            set_egress_port;
        }

        size = 1024;
        alpm = algo_lpm;
    }

    table d_index_to_egress_port_table {
        key = {
            hdr.bridged.index: exact;
        }
        actions = {
            set_egress_port;
            nop;
        }
        const default_action = nop;
        size = DIP_TABLE_SIZE;
    }

    table lb_index_to_egress_port_table {
        key = {
            ig_md.hash_result: exact;
        }
        actions = {
            set_egress_port;
            nop;
        }
        const default_action = nop;
        size = LB_TABLE_SIZE;
    }

    apply {
        hdr.bridged.setValid();
        if(hdr.arp.isValid()) {
            arp_table.apply();
            ig_intr_tm_md.bypass_egress = 1w1;
        }
        else if(hdr.tcp.isValid()) {
            calculate_payload_table.apply();
            vip_lookup_table.apply();
            dip_lookup_table.apply();
            calculate_crc8_table.apply();
            
            
            // preprocess_table.apply();
            offload_connection_table.apply();
            // if(hdr.tcp.syn == 1w1 && ig_md.direction == 3w1) {
            //     respond_syn();
            // }
            // else if(hdr.tcp.rst == 1w1 || hdr.tcp.fin == 1w1) {
            //     skip_oft_and_forward_to_lb();
            // }
            // else if(ig_md.payload_flag == 1w1 && ig_md.direction == 3w1) {
            //     skip_oft_and_forward_to_lb();
            // }
            // else if(ig_md.direction == 3w2) {
            //     forward_to_dest();
            // }
            // else if(ig_md.direction == 3w4) {
            //     send_to_cpu();
            // }
            // else if(ig_md.direction == 3w0) {
            //     skip_oft();
            // }
                                            
        }
        else if(hdr.udp.isValid()){
            ig_intr_tm_md.bypass_egress = 1w1;
        }

        if(ig_md.direction == 0b000) {
            hdr.bridged.forward_to_dest = 1w1;
            
        }
        else if(ig_md.direction == 0b100) {
            hdr.bridged.cpu_flag = 1w1;
        }
        else if(ig_md.direction == 0b001) {
            if(hdr.tcp.syn == 1w1) {
                hdr.bridged.syn_respond = 1w1;
            }
            else if(hdr.tcp.fin == 1w1 || hdr.tcp.rst == 1w1) {
                hdr.bridged.lb_flag = 1w1;
            }
            else if(hdr.bridged.hit_flag == 1w0) {
                hdr.bridged.lb_flag = 1w1;
            }
            else if(hdr.bridged.hit_flag == 1w1 && hdr.bridged.payload_flag == 1w1) {
                hdr.bridged.lb_flag = 1w1;
            }
            else if(hdr.bridged.hit_flag == 1w1){
                hdr.bridged.d_flag = 1w1;
            }
        }
        else if(ig_md.direction == 0b010) {
            if(hdr.tcp.fin == 1w1 || hdr.tcp.rst == 1w1) {
                hdr.bridged.lb_flag = 1w1;
            }
            else if(hdr.bridged.hit_flag == 1w1) {
                hdr.bridged.v_flag = 1w1;
                hdr.bridged.forward_to_dest = 1w1;
            }
            else if(hdr.bridged.hit_flag == 1w0){
                hdr.bridged.lb_flag = 1w1;
            }
        }

        if(hdr.bridged.lb_flag == 1w1) {
            lb_index_to_egress_port_table.apply();
        }
        else if(hdr.bridged.d_flag == 1w1) {
            d_index_to_egress_port_table.apply();
        }
        else if(hdr.bridged.cpu_flag == 1w1) {
            ig_intr_tm_md.ucast_egress_port = 192;
        }
        else if(hdr.bridged.syn_respond == 1w1) {
            hdr.ethernet.dst_addr = hdr.ethernet.src_addr;
            hdr.ethernet.src_addr = 0xabababcdcdcd;
            ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        }
        else if(hdr.bridged.forward_to_dest == 1w1) {
            dest_to_egress_port_table.apply();
        }
    }
}

control SwitchEgress(inout header_t hdr,
        inout egress_metadata_t eg_md,
        in    egress_intrinsic_metadata_t                 eg_intr_md,
        in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    Hash<bit<32>>(HashAlgorithm_t.CRC32) seq_hasher;
    bit<32> seq = seq_hasher.get({hdr.ipv4.src_addr, hdr.tcp.src_port});
    action nop() {}
    action syn_reply() {
        hdr.tcp.syn = 1w1;
        hdr.tcp.ack = 1w1;
        hdr.tcp.ack_no = hdr.tcp.seq_no + 1;
        hdr.tcp.seq_no = seq;
        eg_md.psd_header.src_addr = hdr.ipv4.dst_addr;
        eg_md.psd_header.dst_addr = hdr.ipv4.src_addr;
        hdr.ipv4.src_addr = eg_md.psd_header.src_addr;
        hdr.ipv4.dst_addr = eg_md.psd_header.dst_addr;
        eg_md.psd_header.protocol = IP_PROTOCOLS_TCP;
        eg_md.psd_header.total_len = 32;
        eg_md.dst_port = hdr.tcp.src_port;
        eg_md.psd_header.reserved = 0;
        hdr.tcp.src_port = hdr.tcp.dst_port;
        hdr.tcp.dst_port = eg_md.dst_port;
        hdr.ipv4.total_len = 52;
        hdr.tcp.data_offset = 8;
        hdr.tcp.checksum = 0;
    }

    action options_set() {
        hdr.mss.type = 2;
        hdr.mss.length = 4;
        hdr.mss.mss_value = MSS_VALUE;
        hdr.nop_1.type = 1;
        hdr.nop_2.type = 1;
        hdr.nop_3.type = 1;
        hdr.sack_permitted.type = 4;
        hdr.sack_permitted.length = 2;
        hdr.window_scale.type = 3;
        hdr.window_scale.length = 3;
        hdr.window_scale.ws = WINDOW_SCALE;
    }

    action set_src_ip_port(ipv4_addr_t src_ip, port_t src_port) {
        hdr.ipv4.src_addr = src_ip;
        hdr.tcp.src_port = src_port;
    }

    action set_dst_ip_port(ipv4_addr_t dst_ip, port_t dst_port) {
        hdr.ipv4.dst_addr = dst_ip;
        hdr.tcp.dst_port = dst_port;
    }

    table d_index_to_ip_port_table {
        key = {
            eg_md.bridged.index: exact;
        }

        actions = {
            set_dst_ip_port;
            nop;
        }
        const default_action = nop;
        size = DIP_TABLE_SIZE;
    }
    
    apply {
        if(hdr.tcp.isValid()) {
            if(eg_md.bridged.syn_respond == 1w1) {
                //hdr.tcp_option.setInvalid();
                hdr.mss.setValid();
                hdr.nop_1.setValid();
                hdr.nop_2.setValid();
                hdr.sack_permitted.setValid();
                hdr.nop_3.setValid();
                hdr.window_scale.setValid();
                syn_reply();
                options_set();
            }
            else if(eg_md.bridged.d_flag == 1w1)
            {
                d_index_to_ip_port_table.apply();
            }
            else if(eg_md.bridged.v_flag == 1w1)
            {
                set_src_ip_port(VIRTUAL_IP, VIRTUAL_PORT);
            }
        }
        hdr.bridged.setInvalid();
    }

}

Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    SwitchEgressParser(),
    SwitchEgress(),
    SwitchEgressDeparser()) pipe;

Switch(pipe) main;

#endif