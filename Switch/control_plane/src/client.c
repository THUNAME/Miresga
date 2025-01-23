#include "client.h"

static arp_table_info_t arp_table_info;
static dip_lookup_table_info_t dip_lookup_table_info;
offload_connection_table_info_t offload_connection_table_info;
static dest_to_egress_port_table_info_t dest_to_egress_port_table_info;
static d_index_to_egress_port_table_info_t d_index_to_egress_port_table_info;
static lb_index_to_egress_port_table_info_t lb_index_to_egress_port_table_info;
static d_index_to_ip_port_table_info_t d_index_to_ip_port_table_info;
bf_rt_target_t *dev_tgt = NULL;
bf_rt_session_hdl *session;
const bf_rt_info_hdl *bf_rt_info;
bf_switchd_context_t *switchd_ctx;


void init_switch(char *prog_name) {
    dev_tgt = (bf_rt_target_t *)malloc(sizeof(bf_rt_target_t));
    switchd_ctx = (bf_switchd_context_t *)malloc(sizeof(bf_switchd_context_t));
    dev_tgt->dev_id = 0;
    dev_tgt->pipe_id = BF_DEV_PIPE_ALL;
    char conf_file[256];
    switchd_ctx->install_dir = getenv("SDE_INSTALL");
    sprintf(conf_file, "%s/share/p4/targets/tofino/%s.conf", 
            getenv("SDE_INSTALL"), prog_name);
    switchd_ctx->conf_file = conf_file;
    switchd_ctx->running_in_background = true;
    switchd_ctx->dev_sts_thread = true;
    switchd_ctx->dev_sts_port = 7777;
    switchd_ctx->kernel_pkt = true;
    if(bf_switchd_lib_init(switchd_ctx) != BF_SUCCESS) {
        printf("Failed to init switchd\n");
        exit(1);
    }
}

void init_bf_rt(char *prog_name) {
    bf_status_t status = bf_rt_info_get(dev_tgt->dev_id, prog_name, &bf_rt_info);
    if (status != BF_SUCCESS) {
        printf("Failed to get bf_rt_info\n");
        exit(1);
    }
    status = bf_rt_session_create(&session);
    if (status != BF_SUCCESS) {
        printf("Failed to create session\n");
        exit(1);
    }
}

void init_ports(char *port_json_path) {
    FILE *port_json = fopen(port_json_path, "r");
    if (port_json == NULL) {
        printf("Failed to open port_json\n");
        exit(1);
    }
    fseek(port_json, 0, SEEK_END);
    long port_json_size = ftell(port_json);
    fseek(port_json, 0, SEEK_SET);
    char *port_json_str = (char *)malloc(port_json_size + 1);
    fread(port_json_str, 1, port_json_size, port_json);
    fclose(port_json);
    port_json_str[port_json_size] = '\0';
    cJSON *port_json_array = cJSON_Parse(port_json_str);
    if (port_json_array == NULL) {
        printf("Failed to parse port_json\n");
        exit(1);
    }
    
    int size = cJSON_GetArraySize(port_json_array);
    port_info_t port_info[size];
    for(int i = 0; i < size; i++) {
        cJSON *port_item = cJSON_GetArrayItem(port_json_array, i);
        if(port_item == NULL) {
            printf("Failed to get item\n");
            exit(1);
        }
        cJSON *port_name = cJSON_GetObjectItem(port_item, "port");
        cJSON *port_speed = cJSON_GetObjectItem(port_item, "speed");
        if (port_name == NULL || port_speed == NULL) {
            printf("Failed to get port_name or port_speed\n");
            exit(1);
        }
        port_info[i].port_name = port_name->valuestring;
        port_info[i].port_speed = port_speed->valueint;
        if(port_info[i].port_speed == 100) {
            port_info[i].port_speed = BF_SPEED_100G;
        }
        else if(port_info[i].port_speed == 40) {
            port_info[i].port_speed = BF_SPEED_40G;
        }
        else if(port_info[i].port_speed == 25) {
            port_info[i].port_speed = BF_SPEED_25G;
        }
        else if(port_info[i].port_speed == 10) {
            port_info[i].port_speed = BF_SPEED_10G;
        }
        else {
            printf("Invalid port_speed\n");
            exit(1);
        }
    }

    bf_status_t status;
    for(int i = 0; i < size; i++) {
        bf_pal_front_port_handle_t port_handle;
        status = bf_pm_port_str_to_hdl_get(dev_tgt->dev_id, 
                                           port_info[i].port_name, 
                                           &port_handle);
        if(status != BF_SUCCESS) {
            printf("Failed to get port handle\n");
            exit(1);
        }
        status = bf_pm_port_add(dev_tgt->dev_id, &port_handle, 
                                port_info[i].port_speed, BF_FEC_TYP_RS);
        if(status != BF_SUCCESS) {
            printf("Failed to add port\n");
            exit(1);
        }

        status = bf_pm_port_enable(dev_tgt->dev_id, &port_handle);
        if(status != BF_SUCCESS) {
            printf("Failed to enbable port\n");
            exit(1);
        }
    }

    cJSON_Delete(port_json_array);
    free(port_json_str);
}

void setup_arp_table() {
    bf_status_t status = bf_rt_table_from_name_get(bf_rt_info, 
                                                   "SwitchIngress.arp_table", 
                                                   &arp_table_info.table_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to get arp_table\n");
        exit(1);
    }
    status = bf_rt_table_key_allocate(arp_table_info.table_hdl, 
                                      &arp_table_info.key_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to allocate arp_key\n");
        exit(1);
    }
    status = bf_rt_table_data_allocate(arp_table_info.table_hdl, 
                                       &arp_table_info.data_hdl);
    if(status != BF_SUCCESS) {
        printf("Failed to allocate arp_data\n");
        exit(1);
    }
    status = bf_rt_key_field_id_get(arp_table_info.table_hdl, 
                                    "hdr.arp.opcode", 
                                    &arp_table_info.kid_opcode);
    if (status != BF_SUCCESS) {
        printf("Failed to get kid_arp_opcode\n");
        exit(1);
    }
    status = bf_rt_key_field_id_get(arp_table_info.table_hdl, 
                                    "hdr.arp.target_proto_addr", 
                                    &arp_table_info.kid_target_proto_addr);
    if (status != BF_SUCCESS) {
        printf("Failed to get kid_arp_target_proto_addr\n");
        exit(1);
    }
    status = bf_rt_action_name_to_id(arp_table_info.table_hdl, 
                                     "SwitchIngress.reply_arp", 
                                     &arp_table_info.aid_reply_arp);
    if (status != BF_SUCCESS) {
        printf("Failed to get aid_reply_arp\n");
        exit(1);
    }
    status = bf_rt_data_field_id_with_action_get(arp_table_info.table_hdl, 
                                                 "arp_mac", 
                                                 arp_table_info.aid_reply_arp, 
                                                 &arp_table_info.did_arp_mac);
    if (status != BF_SUCCESS) {
        printf("Failed to get did_arp_mac\n");
        exit(1);
    }
    status = bf_rt_table_action_data_reset(arp_table_info.table_hdl, 
                                           arp_table_info.aid_reply_arp,
                                           &arp_table_info.data_hdl);
    if(status != BF_SUCCESS) {
        printf("Failed to reset data\n");
        exit(1);
    }
}

void setup_dip_lookup_table() {
    bf_status_t status = bf_rt_table_from_name_get(bf_rt_info, 
                                                   "SwitchIngress.dip_lookup_table", 
                                                   &dip_lookup_table_info.table_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to get dip_lookup_table\n");
        exit(1);
    }
    status = bf_rt_table_key_allocate(dip_lookup_table_info.table_hdl, 
                                      &dip_lookup_table_info.key_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to allocate dip_lookup_key\n");
        exit(1);
    }
    status = bf_rt_table_data_allocate(dip_lookup_table_info.table_hdl, 
                                       &dip_lookup_table_info.data_hdl);
    if(status != BF_SUCCESS) {
        printf("Failed to allocate dip_lookup_data\n");
        exit(1);
    }
    status = bf_rt_key_field_id_get(dip_lookup_table_info.table_hdl, 
                                    "hdr.ipv4.src_addr", 
                                    &dip_lookup_table_info.kid_src_ip);
    if (status != BF_SUCCESS) {
        printf("Failed to get kid_src_ip\n");
        exit(1);
    }
    status = bf_rt_key_field_id_get(dip_lookup_table_info.table_hdl, 
                                    "hdr.tcp.src_port", 
                                    &dip_lookup_table_info.kid_src_port);
    if (status != BF_SUCCESS) {
        printf("Failed to get kid_src_port\n");
        exit(1);
    }
    status = bf_rt_action_name_to_id(dip_lookup_table_info.table_hdl, 
                                     "SwitchIngress.dip_hit", 
                                     &dip_lookup_table_info.aid_dip_hit);
    if (status != BF_SUCCESS) {
        printf("Failed to get aid_dip_hit\n");
        exit(1);
    }
    status = bf_rt_table_action_data_reset(dip_lookup_table_info.table_hdl,
                                           dip_lookup_table_info.aid_dip_hit,
                                           &dip_lookup_table_info.data_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to reset dip_lookup_table_data");
        exit(1);
    }
}

void setup_offload_connection_table() {
    bf_status_t status = bf_rt_table_from_name_get(bf_rt_info, 
                                                   "SwitchIngress.offload_connection_table", 
                                                   &offload_connection_table_info.table_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to get offload_connection_table\n");
        exit(1);
    }
    status = bf_rt_key_field_id_get(offload_connection_table_info.table_hdl, 
                                    "ig_md.cip", 
                                    &offload_connection_table_info.kid_cip);
    if (status != BF_SUCCESS) {
        printf("Failed to get kid_cip\n");
        exit(1);
    }
    status = bf_rt_key_field_id_get(offload_connection_table_info.table_hdl, 
                                    "ig_md.cport", 
                                    &offload_connection_table_info.kid_cport);
    if (status != BF_SUCCESS) {
        printf("Failed to get kid_cport\n");
        exit(1);
    }
    status = bf_rt_action_name_to_id(offload_connection_table_info.table_hdl, 
                                     "SwitchIngress.oft_hit", 
                                     &offload_connection_table_info.aid_oft_hit);
    if (status != BF_SUCCESS) {
        printf("Failed to get aid_oft_hit\n");
        exit(1);
    }
    status = bf_rt_data_field_id_with_action_get(offload_connection_table_info.table_hdl, 
                                                 "d_index",
                                                 offload_connection_table_info.aid_oft_hit, 
                                                 &offload_connection_table_info.did_d_index);
    if (status != BF_SUCCESS) {
        printf("Failed to get did_oft_d_index\n");
        exit(1);
    }
    for(int i = 0; i < 256; ++i) {
        status = bf_rt_table_key_allocate(offload_connection_table_info.table_hdl, 
                                          &offload_connection_table_info.key_hdl[i]);
        if (status != BF_SUCCESS) {
            printf("Failed to allocate offload_connection_key\n");
            exit(1);
        }
        status = bf_rt_table_data_allocate(offload_connection_table_info.table_hdl, 
                                           &offload_connection_table_info.data_hdl[i]);
        if(status != BF_SUCCESS) {
            printf("Failed to allocate offload_connection_data\n");
            exit(1);
        }
        status = bf_rt_table_action_data_reset(offload_connection_table_info.table_hdl,
                                               offload_connection_table_info.aid_oft_hit,
                                               &offload_connection_table_info.data_hdl[i]);
        if(status != BF_SUCCESS) {
            printf("Failed to reset offload_connection_data\n");
            exit(1);
        }
    }
}

void setup_dest_to_egress_port_table() {
    bf_status_t status = bf_rt_table_from_name_get(bf_rt_info, 
                                                   "SwitchIngress.dest_to_egress_port_table", 
                                                   &dest_to_egress_port_table_info.table_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to get dest_to_egress_port_table\n");
        exit(1);
    }
    status = bf_rt_table_key_allocate(dest_to_egress_port_table_info.table_hdl, 
                                      &dest_to_egress_port_table_info.key_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to allocate dest_to_egress_port_key\n");
        exit(1);
    }
    status = bf_rt_table_data_allocate(dest_to_egress_port_table_info.table_hdl, 
                                       &dest_to_egress_port_table_info.data_hdl);
    if(status != BF_SUCCESS) {
        printf("Failed to allocate dest_to_egress_port_data\n");
        exit(1);
    }
    status = bf_rt_key_field_id_get(dest_to_egress_port_table_info.table_hdl, 
                                    "hdr.ipv4.dst_addr", 
                                    &dest_to_egress_port_table_info.kid_dst_addr);
    if (status != BF_SUCCESS) {
        printf("Failed to get kid_dst_addr\n");
        exit(1);
    }
    status = bf_rt_action_name_to_id(dest_to_egress_port_table_info.table_hdl, 
                                     "SwitchIngress.set_egress_port", 
                                     &dest_to_egress_port_table_info.aid_set_egress_port);
    if (status != BF_SUCCESS) {
        printf("Failed to get aid_set_egres_port\n");
        exit(1);
    }
    status = bf_rt_data_field_id_with_action_get(dest_to_egress_port_table_info.table_hdl, 
                                                 "src_mac", 
                                                 dest_to_egress_port_table_info.aid_set_egress_port, 
                                                 &dest_to_egress_port_table_info.did_src_mac);
    if (status != BF_SUCCESS) {
        printf("Failed to get did_src_mac\n");
        exit(1);
    }
    status = bf_rt_data_field_id_with_action_get(dest_to_egress_port_table_info.table_hdl, 
                                                 "dst_mac", 
                                                 dest_to_egress_port_table_info.aid_set_egress_port, 
                                                 &dest_to_egress_port_table_info.did_dst_mac);
    if (status != BF_SUCCESS) {
        printf("Failed to get did_dst_mac\n");
        exit(1);
    }
    status = bf_rt_data_field_id_with_action_get(dest_to_egress_port_table_info.table_hdl, 
                                                 "dst_port", 
                                                 dest_to_egress_port_table_info.aid_set_egress_port, 
                                                 &dest_to_egress_port_table_info.did_dst_port);
    if (status != BF_SUCCESS) {
        printf("Failed to get did_dst_port\n");
        exit(1);
    }
    status = bf_rt_table_action_data_reset(dest_to_egress_port_table_info.table_hdl,
                                           dest_to_egress_port_table_info.aid_set_egress_port,
                                           &dest_to_egress_port_table_info.data_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to reset dest_to_egress_port_table_data\n");
        exit(1);
    }
}

void setup_d_index_to_egress_port_table() {
    bf_status_t status = bf_rt_table_from_name_get(bf_rt_info, 
                                                   "SwitchIngress.d_index_to_egress_port_table", 
                                                   &d_index_to_egress_port_table_info.table_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to get d_index_to_egress_port_table\n");
        exit(1);
    }
    status = bf_rt_table_key_allocate(d_index_to_egress_port_table_info.table_hdl, 
                                      &d_index_to_egress_port_table_info.key_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to allocate d_index_to_egress_port_key\n");
        exit(1);
    }
    status = bf_rt_table_data_allocate(d_index_to_egress_port_table_info.table_hdl, 
                                       &d_index_to_egress_port_table_info.data_hdl);
    if(status != BF_SUCCESS) {
        printf("Failed to allocate d_index_to_egress_port_data\n");
        exit(1);
    }
    status = bf_rt_key_field_id_get(d_index_to_egress_port_table_info.table_hdl, 
                                    "hdr.bridged.index", 
                                    &d_index_to_egress_port_table_info.kid_d_index);
    if (status != BF_SUCCESS) {
        printf("Failed to get kid_d_index\n");
        exit(1);
    }
    status = bf_rt_action_name_to_id(d_index_to_egress_port_table_info.table_hdl, 
                                     "SwitchIngress.set_egress_port", 
                                     &d_index_to_egress_port_table_info.aid_set_egress_port);
    if (status != BF_SUCCESS) {
        printf("Failed to get aid_set_egres_port\n");
        exit(1);
    }
    status = bf_rt_data_field_id_with_action_get(d_index_to_egress_port_table_info.table_hdl, 
                                                 "src_mac", 
                                                 d_index_to_egress_port_table_info.aid_set_egress_port, 
                                                 &d_index_to_egress_port_table_info.did_src_mac);
    if (status != BF_SUCCESS) {
        printf("Failed to get did_src_mac\n");
        exit(1);
    }
    status = bf_rt_data_field_id_with_action_get(d_index_to_egress_port_table_info.table_hdl, 
                                                 "dst_mac", 
                                                 d_index_to_egress_port_table_info.aid_set_egress_port, 
                                                 &d_index_to_egress_port_table_info.did_dst_mac);
    if (status != BF_SUCCESS) {
        printf("Failed to get did_dst_mac\n");
        exit(1);
    }
    status = bf_rt_data_field_id_with_action_get(d_index_to_egress_port_table_info.table_hdl, 
                                                 "dst_port", 
                                                 d_index_to_egress_port_table_info.aid_set_egress_port, 
                                                 &d_index_to_egress_port_table_info.did_dst_port);
    if (status != BF_SUCCESS) {
        printf("Failed to get did_dst_port\n");
        exit(1);
    }
    status = bf_rt_table_action_data_reset(d_index_to_egress_port_table_info.table_hdl,
                                           d_index_to_egress_port_table_info.aid_set_egress_port,
                                           &d_index_to_egress_port_table_info.data_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to reset d_index_to_egress_port_table_data\n");
        exit(1);
    }
}

void setup_lb_index_to_egress_port_table() {
    bf_status_t status = bf_rt_table_from_name_get(bf_rt_info, 
                                                   "SwitchIngress.lb_index_to_egress_port_table", 
                                                   &lb_index_to_egress_port_table_info.table_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to get lb_index_to_egress_port_table\n");
        exit(1);
    }
    status = bf_rt_key_field_id_get(lb_index_to_egress_port_table_info.table_hdl, 
                                    "ig_md.hash_result", 
                                    &lb_index_to_egress_port_table_info.kid_lb_index);
    if (status != BF_SUCCESS) {
        printf("Failed to get kid_lb_index\n");
        exit(1);
    }
    status = bf_rt_action_name_to_id(lb_index_to_egress_port_table_info.table_hdl, 
                                     "SwitchIngress.set_egress_port", 
                                     &lb_index_to_egress_port_table_info.aid_set_egress_port);
    if (status != BF_SUCCESS) {
        printf("Failed to get aid_set_egres_port\n");
        exit(1);
    }
    status = bf_rt_data_field_id_with_action_get(lb_index_to_egress_port_table_info.table_hdl, 
                                                 "src_mac", 
                                                 lb_index_to_egress_port_table_info.aid_set_egress_port, 
                                                 &lb_index_to_egress_port_table_info.did_src_mac);
    if (status != BF_SUCCESS) {
        printf("Failed to get did_src_mac\n");
        exit(1);
    }
    status = bf_rt_data_field_id_with_action_get(lb_index_to_egress_port_table_info.table_hdl, 
                                                 "dst_mac", 
                                                 lb_index_to_egress_port_table_info.aid_set_egress_port,
                                                 &lb_index_to_egress_port_table_info.did_dst_mac);
    if (status != BF_SUCCESS) {
        printf("Failed to get did_dst_mac\n");
        exit(1);
    }
    status = bf_rt_data_field_id_with_action_get(lb_index_to_egress_port_table_info.table_hdl, 
                                                 "dst_port", 
                                                 lb_index_to_egress_port_table_info.aid_set_egress_port, 
                                                 &lb_index_to_egress_port_table_info.did_dst_port);
    if (status != BF_SUCCESS) {
        printf("Failed to get did_dst_port\n");
        exit(1);
    }
    status = bf_rt_table_key_allocate(lb_index_to_egress_port_table_info.table_hdl, 
                                      &lb_index_to_egress_port_table_info.key_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to allocate lb_index_to_egress_port_key\n");
        exit(1);
    }
    status = bf_rt_table_data_allocate(lb_index_to_egress_port_table_info.table_hdl, 
                                       &lb_index_to_egress_port_table_info.data_hdl);
    if(status != BF_SUCCESS) {
        printf("Failed to allocate lb_index_to_egress_port_data\n");
        exit(1);
    }
    status = bf_rt_table_action_data_reset(lb_index_to_egress_port_table_info.table_hdl,
                                           lb_index_to_egress_port_table_info.aid_set_egress_port,
                                           &lb_index_to_egress_port_table_info.data_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to reset lb_index_to_egress_port_table_data\n");
        exit(1);
    }
}

void setup_d_index_to_ip_port_table() {
    bf_status_t status = bf_rt_table_from_name_get(bf_rt_info, 
                                                   "SwitchEgress.d_index_to_ip_port_table", 
                                                   &d_index_to_ip_port_table_info.table_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to get d_index_to_ip_port_table\n");
        exit(1);
    }
    status = bf_rt_table_key_allocate(d_index_to_ip_port_table_info.table_hdl, 
                                      &d_index_to_ip_port_table_info.key_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to allocate d_index_to_ip_port_key\n");
        exit(1);
    }
    status = bf_rt_table_data_allocate(d_index_to_ip_port_table_info.table_hdl, 
                                       &d_index_to_ip_port_table_info.data_hdl);
    if(status != BF_SUCCESS) {
        printf("Failed to allocate d_index_to_ip_port_data\n");
        exit(1);
    }
    status = bf_rt_key_field_id_get(d_index_to_ip_port_table_info.table_hdl, 
                                    "eg_md.bridged.index", 
                                    &d_index_to_ip_port_table_info.kid_d_index);
    if (status != BF_SUCCESS) {
        printf("Failed to get kid_d_index\n");
        exit(1);
    }
    status = bf_rt_action_name_to_id(d_index_to_ip_port_table_info.table_hdl, 
                                     "SwitchEgress.set_dst_ip_port", 
                                     &d_index_to_ip_port_table_info.aid_set_dst_ip_port);
    if (status != BF_SUCCESS) {
        printf("Failed to get aid_set_ip_port\n");
        exit(1);
    }
    status = bf_rt_data_field_id_with_action_get(d_index_to_ip_port_table_info.table_hdl, 
                                                 "dst_ip", 
                                                 d_index_to_ip_port_table_info.aid_set_dst_ip_port, 
                                                 &d_index_to_ip_port_table_info.did_dst_ip);
    if (status != BF_SUCCESS) {
        printf("Failed to get did_dst_ip\n");
        exit(1);
    }
    status = bf_rt_data_field_id_with_action_get(d_index_to_ip_port_table_info.table_hdl, 
                                                 "dst_port", 
                                                 d_index_to_ip_port_table_info.aid_set_dst_ip_port, 
                                                 &d_index_to_ip_port_table_info.did_dst_port);
    if (status != BF_SUCCESS) {
        printf("Failed to get did_dst_port\n");
        exit(1);
    }
    status = bf_rt_table_action_data_reset(d_index_to_ip_port_table_info.table_hdl,
                                           d_index_to_ip_port_table_info.aid_set_dst_ip_port,
                                           &d_index_to_ip_port_table_info.data_hdl);
    if (status != BF_SUCCESS) {
        printf("Failed to reset dest_to_egress_port_table_data\n");
        exit(1);
    }
}

void add_arp_table_entry(int size, arp_table_entry_t *arp_table_entry) {
    bf_status_t status;
    for(int i = 0; i < size; ++i) {
        status = bf_rt_key_field_set_value(arp_table_info.key_hdl, 
                                           arp_table_info.kid_opcode, 
                                           arp_table_entry[i].opcode);
        if (status != BF_SUCCESS) {
            printf("Failed to set arp_key\n");
            exit(1);
        }
        status = bf_rt_key_field_set_value(arp_table_info.key_hdl, 
                                           arp_table_info.kid_target_proto_addr, 
                                           arp_table_entry[i].target_proto_addr);
        if (status != BF_SUCCESS) {
            printf("Failed to set arp_key\n");
            exit(1);
        }
        status = bf_rt_table_action_data_reset(arp_table_info.table_hdl,
                                               arp_table_info.aid_reply_arp,
                                               &arp_table_info.data_hdl);
        status = bf_rt_data_field_set_value(arp_table_info.data_hdl, 
                                            arp_table_info.did_arp_mac, 
                                            arp_table_entry[i].arp_mac);
        if (status != BF_SUCCESS) {
            printf("Failed to set arp_data\n");
            exit(1);
        }
        status = bf_rt_table_entry_add(arp_table_info.table_hdl, 
                                       session,
                                       dev_tgt,
                                       arp_table_info.key_hdl, 
                                       arp_table_info.data_hdl);
        if (status != BF_SUCCESS) {
            printf("Failed to add arp_entry\n");
            exit(1);
        }
        status = bf_rt_session_complete_operations(session);
        if (status != BF_SUCCESS) {
            printf("Failed to complete operations\n");
            exit(1);
        }
    }
}

void add_dip_lookup_table_entry(int size, dip_lookup_table_entry_t *dip_lookup_table_entry) {
    bf_status_t status;
    for(int i = 0; i < size; i++) {
        status = bf_rt_key_field_set_value(dip_lookup_table_info.key_hdl, 
                                           dip_lookup_table_info.kid_src_ip, 
                                           dip_lookup_table_entry[i].src_ip);
        if (status != BF_SUCCESS) {
            printf("Failed to set src_ip\n");
            exit(1);
        }
        status = bf_rt_key_field_set_value(dip_lookup_table_info.key_hdl, 
                                           dip_lookup_table_info.kid_src_port, 
                                           dip_lookup_table_entry[i].src_port);
        if (status != BF_SUCCESS) {
            printf("Failed to set src_port\n");
            exit(1);
        }
        status = bf_rt_table_entry_add(dip_lookup_table_info.table_hdl, 
                                       session,
                                       dev_tgt,
                                       dip_lookup_table_info.key_hdl, 
                                       dip_lookup_table_info.data_hdl);
        if (status != BF_SUCCESS) {
            printf("Failed to add dip_lookup_table_entry\n");
            exit(1);
        }
        status = bf_rt_session_complete_operations(session);
        if (status != BF_SUCCESS) {
            printf("Failed to complete operations\n");
            exit(1);
        }
    }
}

void add_dest_to_egress_port_table_entry(int size, dest_to_egress_port_table_entry_t *dest_to_egress_port_table_entry) {
    bf_status_t status;
    for(int i = 0; i < size; i++) {
        status = bf_rt_key_field_set_value_lpm(dest_to_egress_port_table_info.key_hdl, 
                                               dest_to_egress_port_table_info.kid_dst_addr, 
                                               dest_to_egress_port_table_entry[i].dst_addr, 
                                               dest_to_egress_port_table_entry[i].prefix_len);
        if (status != BF_SUCCESS) {
            printf("Failed to set dst_addr\n");
            exit(1);
        }
        status = bf_rt_data_field_set_value(dest_to_egress_port_table_info.data_hdl, 
                                            dest_to_egress_port_table_info.did_src_mac, 
                                            dest_to_egress_port_table_entry[i].src_mac);
        if (status != BF_SUCCESS) {
            printf("Failed to set src_mac\n");
            exit(1);
        }
        status = bf_rt_data_field_set_value(dest_to_egress_port_table_info.data_hdl, 
                                            dest_to_egress_port_table_info.did_dst_mac, 
                                            dest_to_egress_port_table_entry[i].dst_mac);
        if (status != BF_SUCCESS) {
            printf("Failed to set dst_mac\n");
            exit(1);
        }
        status = bf_rt_data_field_set_value(dest_to_egress_port_table_info.data_hdl, 
                                            dest_to_egress_port_table_info.did_dst_port, 
                                            dest_to_egress_port_table_entry[i].dst_port);
        if (status != BF_SUCCESS) {
            printf("Failed to set dst_port\n");
            exit(1);
        }
        status = bf_rt_table_entry_add(dest_to_egress_port_table_info.table_hdl, 
                                       session,
                                       dev_tgt,
                                       dest_to_egress_port_table_info.key_hdl, 
                                       dest_to_egress_port_table_info.data_hdl);
        if (status != BF_SUCCESS) {
            printf("Failed to add dest_to_egress_port_table_entry\n");
            exit(1);
        }
        status = bf_rt_session_complete_operations(session);
        if (status != BF_SUCCESS) {
            printf("Failed to complete operations\n");
            exit(1);
        }
    }
}

void add_d_index_to_egress_port_table_entry(int size, d_index_to_egress_port_table_entry_t *d_index_to_egress_port_table_entry) {
    bf_status_t status;
    for(int i = 0; i < size; i++) {
        status = bf_rt_key_field_set_value(d_index_to_egress_port_table_info.key_hdl, 
                                           d_index_to_egress_port_table_info.kid_d_index, 
                                           d_index_to_egress_port_table_entry[i].d_index);
        if (status != BF_SUCCESS) {
            printf("Failed to set d_index\n");
            exit(1);
        }
        status = bf_rt_data_field_set_value(d_index_to_egress_port_table_info.data_hdl, 
                                            d_index_to_egress_port_table_info.did_src_mac, 
                                            INBOUND_SRC_MAC);
        if (status != BF_SUCCESS) {
            printf("Failed to set src_mac\n");
            exit(1);
        }
        status = bf_rt_data_field_set_value(d_index_to_egress_port_table_info.data_hdl, 
                                            d_index_to_egress_port_table_info.did_dst_mac, 
                                            d_index_to_egress_port_table_entry[i].dst_mac);
        if (status != BF_SUCCESS) {
            printf("Failed to set dst_mac\n");
            exit(1);
        }
        status = bf_rt_data_field_set_value(d_index_to_egress_port_table_info.data_hdl, 
                                            d_index_to_egress_port_table_info.did_dst_port, 
                                            d_index_to_egress_port_table_entry[i].dst_port);
        if (status != BF_SUCCESS) {
            printf("Failed to set dst_port\n");
            exit(1);
        }
        status = bf_rt_table_entry_add(d_index_to_egress_port_table_info.table_hdl, 
                                       session,
                                       dev_tgt,
                                       d_index_to_egress_port_table_info.key_hdl, 
                                       d_index_to_egress_port_table_info.data_hdl);
        if (status != BF_SUCCESS) {
            printf("Failed to add d_index_to_egress_port_table_entry\n");
            exit(1);
        }
        status = bf_rt_session_complete_operations(session);
        if (status != BF_SUCCESS) {
            printf("Failed to complete operations\n");
            exit(1);
        }
    }
    
}

void add_lb_index_to_egress_port_table_entry(int size, lb_index_to_egress_port_table_entry_t *lb_index_to_egress_port_table_entry) {
    bf_status_t status;
    for(int i = 0; i < size; i++) {
        status = bf_rt_table_key_reset(lb_index_to_egress_port_table_info.table_hdl,
                                       &lb_index_to_egress_port_table_info.key_hdl);
        if (status != BF_SUCCESS) {
            printf("Failed to reset lb_index\n");
            exit(1);
        }
        status = bf_rt_key_field_set_value(lb_index_to_egress_port_table_info.key_hdl, 
                                           lb_index_to_egress_port_table_info.kid_lb_index, 
                                           lb_index_to_egress_port_table_entry[i].lb_index);
        if (status != BF_SUCCESS) {
            printf("Failed to set lb_index\n");
            exit(1);
        }
        status = bf_rt_table_action_data_reset(lb_index_to_egress_port_table_info.table_hdl, 
                                               lb_index_to_egress_port_table_info.aid_set_egress_port,
                                               &lb_index_to_egress_port_table_info.data_hdl);
        if (status != BF_SUCCESS) {
            printf("Failed to reset lb_index\n");
            exit(1);
        }
        status = bf_rt_data_field_set_value(lb_index_to_egress_port_table_info.data_hdl, 
                                            lb_index_to_egress_port_table_info.did_src_mac, 
                                            INBOUND_SRC_MAC);
        if (status != BF_SUCCESS) {
            printf("Failed to set src_mac\n");
            exit(1);
        }
        status = bf_rt_data_field_set_value(lb_index_to_egress_port_table_info.data_hdl, 
                                            lb_index_to_egress_port_table_info.did_dst_mac, 
                                            lb_index_to_egress_port_table_entry[i].dst_mac);
        if (status != BF_SUCCESS) {
            printf("Failed to set dst_mac\n");
            exit(1);
        }
        status = bf_rt_data_field_set_value(lb_index_to_egress_port_table_info.data_hdl, 
                                            lb_index_to_egress_port_table_info.did_dst_port, 
                                            lb_index_to_egress_port_table_entry[i].dst_port);
        if (status != BF_SUCCESS) {
            printf("Failed to set dst_port\n");
            exit(1);
        }
        status = bf_rt_table_entry_add(lb_index_to_egress_port_table_info.table_hdl, 
                                       session,
                                       dev_tgt,
                                       lb_index_to_egress_port_table_info.key_hdl, 
                                       lb_index_to_egress_port_table_info.data_hdl);
        if (status != BF_SUCCESS) {
            printf("Failed to add lb_index_to_egress_port_table_entry\n");
            exit(1);
        }
        status = bf_rt_session_complete_operations(session);
        if (status != BF_SUCCESS) {
            printf("Failed to complete operations\n");
            exit(1);
        }
    }
}

void add_d_index_to_ip_port_table_entry(int size, d_index_to_ip_port_table_entry_t *d_index_to_ip_port_table_entry) {
    bf_status_t status;
    for(int i = 0; i < size; i++) {
        status = bf_rt_key_field_set_value(d_index_to_ip_port_table_info.key_hdl, 
                                           d_index_to_ip_port_table_info.kid_d_index, 
                                           d_index_to_ip_port_table_entry[i].d_index);
        if (status != BF_SUCCESS) {
            printf("Failed to set d_index\n");
            exit(1);
        }
        status = bf_rt_data_field_set_value(d_index_to_ip_port_table_info.data_hdl, 
                                            d_index_to_ip_port_table_info.did_dst_ip, 
                                            d_index_to_ip_port_table_entry[i].dst_ip);
        if (status != BF_SUCCESS) {
            printf("Failed to set dst_ip\n");
            exit(1);
        }
        status = bf_rt_data_field_set_value(d_index_to_ip_port_table_info.data_hdl, 
                                            d_index_to_ip_port_table_info.did_dst_port, 
                                            d_index_to_ip_port_table_entry[i].dst_port);
        if (status != BF_SUCCESS) {
            printf("Failed to set dst_port\n");
            exit(1);
        }
        status = bf_rt_table_entry_add(d_index_to_ip_port_table_info.table_hdl, 
                                       session,
                                       dev_tgt,
                                       d_index_to_ip_port_table_info.key_hdl, 
                                       d_index_to_ip_port_table_info.data_hdl);
        if (status != BF_SUCCESS) {
            printf("Failed to add d_index_to_ip_port_table_entry\n");
            exit(1);
        }
        status = bf_rt_session_complete_operations(session);
        if (status != BF_SUCCESS) {
            printf("Failed to complete operations\n");
            exit(1);
        }
    }
}