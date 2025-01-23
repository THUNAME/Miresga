#ifndef CLIENT_H_
#define CLIENT_H_

#include <bf_switchd/bf_switchd.h>
#include <bf_rt/bf_rt_init.h>
#include <bf_rt/bf_rt_session.h>
// #include <bf_rt/bf_rt_common.h>
#include <bf_rt/bf_rt_table_key.h>
#include <bf_rt/bf_rt_table_data.h>
#include <bf_rt/bf_rt_table.h>
#include <bf_pm/bf_pm_intf.h>
#include <mc_mgr/mc_mgr_intf.h>
#include <tofino/pdfixed/pd_conn_mgr.h>
#include <tofino/pdfixed/pd_mirror.h>
#include <cJson/cJSON.h>

#define INBOUND_SRC_MAC  0x0c42a14aff02
#define OUTBOUND_SRC_MAC 0x0c42a14aff01

typedef struct arp_table_info_s {
    const bf_rt_table_hdl *table_hdl;
    bf_rt_id_t kid_opcode;
    bf_rt_id_t kid_target_proto_addr;
    bf_rt_id_t aid_reply_arp;
    bf_rt_id_t did_arp_mac;
    bf_rt_table_key_hdl *key_hdl;
    bf_rt_table_data_hdl *data_hdl;
} arp_table_info_t;

typedef struct arp_table_entry_s {
    uint16_t opcode;
    uint32_t target_proto_addr;
    uint64_t arp_mac;
} arp_table_entry_t;

typedef struct dip_lookup_table_info_s {
    const bf_rt_table_hdl *table_hdl;
    bf_rt_id_t kid_src_ip;
    bf_rt_id_t kid_src_port;
    bf_rt_id_t aid_dip_hit;
    bf_rt_table_key_hdl *key_hdl;
    bf_rt_table_data_hdl *data_hdl;
} dip_lookup_table_info_t;

typedef struct dip_lookup_table_entry_s {
    uint32_t src_ip;
    uint16_t src_port;
} dip_lookup_table_entry_t;

typedef struct offload_connection_table_info_s {
    const bf_rt_table_hdl *table_hdl;
    bf_rt_id_t kid_cip;
    bf_rt_id_t kid_cport;
    bf_rt_id_t aid_oft_hit;
    bf_rt_id_t did_d_index;
    bf_rt_table_key_hdl *key_hdl[256];
    bf_rt_table_data_hdl *data_hdl[256];
} offload_connection_table_info_t;

typedef struct offload_connection_table_entry_s {
    uint32_t cip;
    uint16_t cport;
    uint32_t d_index;
    bool del_flag;
} offload_connection_table_entry_t;

typedef struct dest_to_egress_port_table_info_s {
    const bf_rt_table_hdl *table_hdl;
    bf_rt_id_t kid_dst_addr;
    bf_rt_id_t aid_set_egress_port;
    bf_rt_id_t did_src_mac;
    bf_rt_id_t did_dst_mac;
    bf_rt_id_t did_dst_port;
    bf_rt_table_key_hdl *key_hdl;
    bf_rt_table_data_hdl *data_hdl;
} dest_to_egress_port_table_info_t;

typedef struct dest_to_egress_port_table_entry_s {
    uint32_t dst_addr;
    uint16_t prefix_len;
    uint64_t src_mac;
    uint64_t dst_mac;
    uint16_t dst_port;
} dest_to_egress_port_table_entry_t;

typedef struct d_index_to_egress_port_table_info_s {
    const bf_rt_table_hdl *table_hdl;
    bf_rt_id_t kid_d_index;
    bf_rt_id_t aid_set_egress_port;
    bf_rt_id_t did_src_mac;
    bf_rt_id_t did_dst_mac;
    bf_rt_id_t did_dst_port;
    bf_rt_table_key_hdl *key_hdl;
    bf_rt_table_data_hdl *data_hdl;
} d_index_to_egress_port_table_info_t;

typedef struct d_index_to_egress_port_table_entry_s {
    uint32_t d_index;
    uint64_t src_mac;
    uint64_t dst_mac;
    uint16_t dst_port;
} d_index_to_egress_port_table_entry_t;

typedef struct lb_index_to_egress_port_table_info_s {
    const bf_rt_table_hdl *table_hdl;
    bf_rt_id_t kid_lb_index;
    bf_rt_id_t aid_set_egress_port;
    bf_rt_id_t did_src_mac;
    bf_rt_id_t did_dst_mac;
    bf_rt_id_t did_dst_port;
    bf_rt_table_key_hdl *key_hdl;
    bf_rt_table_data_hdl *data_hdl;
} lb_index_to_egress_port_table_info_t;

typedef struct lb_index_to_egress_port_table_entry_s {
    uint8_t lb_index;
    uint64_t src_mac;
    uint64_t dst_mac;
    uint16_t dst_port;
} lb_index_to_egress_port_table_entry_t;

typedef struct d_index_to_ip_port_table_info_s {
    const bf_rt_table_hdl *table_hdl;
    bf_rt_id_t kid_d_index;
    bf_rt_id_t aid_set_dst_ip_port;
    bf_rt_id_t did_dst_ip;
    bf_rt_id_t did_dst_port;
    bf_rt_table_key_hdl *key_hdl;
    bf_rt_table_data_hdl *data_hdl;
} d_index_to_ip_port_table_info_t;

typedef struct d_index_to_ip_port_table_entry_s {
    uint32_t d_index;
    uint32_t dst_ip;
    uint16_t dst_port;
} d_index_to_ip_port_table_entry_t;

typedef struct port_info_s {
    char *port_name;
    bf_port_speed_t port_speed;
} port_info_t;

extern offload_connection_table_info_t offload_connection_table_info;
extern bf_rt_target_t *dev_tgt;
extern bf_rt_session_hdl *session;
extern void init_switch(char *prog_name);
extern void init_bf_rt(char *prog_name);
extern void init_ports(char *port_path);
extern void setup_arp_table();
extern void add_arp_table_entry(int size, arp_table_entry_t *arp_table_entry);
extern void setup_dip_lookup_table();
extern void add_dip_lookup_table_entry(int size, 
                                       dip_lookup_table_entry_t *dip_lookup_table_entry);
extern void setup_offload_connection_table();
extern void setup_dest_to_egress_port_table();
extern void add_dest_to_egress_port_table_entry(int size, 
                                                dest_to_egress_port_table_entry_t *dest_to_egress_port_table_entry);
extern void setup_d_index_to_egress_port_table();
extern void add_d_index_to_egress_port_table_entry(int size, 
                                                   d_index_to_egress_port_table_entry_t *d_index_to_egress_port_table_entry);
extern void setup_lb_index_to_egress_port_table();
extern void add_lb_index_to_egress_port_table_entry(int size, 
                                                    lb_index_to_egress_port_table_entry_t *lb_index_to_egress_port_table_entry);
extern void setup_d_index_to_ip_port_table();
extern void add_d_index_to_ip_port_table_entry(int size, 
                                        d_index_to_ip_port_table_entry_t *d_index_to_ip_port_table_entry);

#endif