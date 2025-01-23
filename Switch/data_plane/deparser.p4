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

#ifndef _DEPARSER_P4
#define _DEPARSER_P4

#include "headers.p4"

control SwitchIngressDeparser(packet_out pkt,
        inout header_t hdr,
        in ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
    apply {
        pkt.emit(hdr.bridged);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.arp);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

control SwitchEgressDeparser(packet_out pkt,
        inout header_t hdr,
        in egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    Checksum() ipv4_checksum;
    Checksum() tcp_checksum;
    apply {
        if(hdr.ipv4.isValid()){
            hdr.ipv4.hdr_checksum = ipv4_checksum.update(
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        }
        if(eg_md.bridged.syn_respond == 1w1) {
            hdr.tcp.checksum = tcp_checksum.update(
                {
                    eg_md.psd_header.src_addr,
                    eg_md.psd_header.dst_addr,
                    eg_md.psd_header.reserved,
                    eg_md.psd_header.protocol,
                    eg_md.psd_header.total_len,
                    hdr.tcp.src_port,
                    hdr.tcp.dst_port,
                    hdr.tcp.seq_no,
                    hdr.tcp.ack_no,
                    hdr.tcp.data_offset,
                    hdr.tcp.res,
                    hdr.tcp.urg,
                    hdr.tcp.ack,
                    hdr.tcp.psh,
                    hdr.tcp.rst,
                    hdr.tcp.syn,
                    hdr.tcp.fin,
                    hdr.tcp.window,
                    hdr.tcp.checksum,
                    hdr.tcp.urgent_ptr,
                    hdr.mss,
                    hdr.nop_1,
                    hdr.nop_2,
                    hdr.sack_permitted,
                    hdr.nop_3,
                    hdr.window_scale
                }
            );
        }
        else{
            hdr.tcp.checksum = tcp_checksum.update(
                {
                    hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr,
                    hdr.tcp.src_port,
                    hdr.tcp.dst_port,
                    eg_md.tcp_udp_checksum    
                }
            );
            
        }
        
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.mss);
        pkt.emit(hdr.nop_1);
        pkt.emit(hdr.nop_2);
        pkt.emit(hdr.sack_permitted);
        pkt.emit(hdr.nop_3);
        pkt.emit(hdr.window_scale);
    }
}

#endif