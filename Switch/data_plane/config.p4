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

#ifndef _CONFIG_P4
#define _CONFIG_P4
 


// Typedef
typedef bit<8>   pkt_type_t;
typedef bit<8>   ip_protocol_t;
typedef bit<12>  vlan_id_t;
typedef bit<16>  port_t;
typedef bit<16>  ether_type_t;
typedef bit<32>  seq_num_t;
typedef bit<32>  ack_num_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<48>  mac_addr_t;
typedef bit<128> ipv6_addr_t;

// Constants
const ether_type_t  ETHERTYPE_IPV4        = 16w0x0800;
const ether_type_t  ETHERTYPE_ARP         = 16w0x0806;
const ether_type_t  ETHERTYPE_IPV6        = 16w0x86dd;
const ether_type_t  ETHERTYPE_VLAN        = 16w0x8100;
const ip_protocol_t IP_PROTOCOLS_ICMP     = 1;
const ip_protocol_t IP_PROTOCOLS_TCP      = 6;
const ip_protocol_t IP_PROTOCOLS_UDP      = 17;
const bit<16>       MSS_VALUE             = 1460;
const bit<8>        WINDOW_SCALE          = 7;

// define
#define DIP_TABLE_SIZE                       256
#define LB_TABLE_SIZE                        256
#define OFFLOADED_CONNECTION_TABLE_SIZE      368640
#define VIRTUAL_IP                           0x0a00010A
#define VIRTUAL_PORT                         80
#define SWITCH_IP                            0x0a0001FE
#define SWITCH_PORT                          12345

#endif