#include "client.h"
#include "controller.h"

#define PROG_NAME "l7lb_switch"
#define PORT_PATH "config/port.json"
#define RULE_PATH "config/rule.json"
#define D_INDEX_PATH "config/d_index.json"
#define V_INFO_PATH "config/v_info.json"
#define ARP_TABLE_PATH "config/arp_table.json"
#define LB_INDEX_PATH "config/lb_index.json"
#define DEST_TO_EGRESS_PATH "config/dest_to_egress.json"
#define LOCAL_IP "10.0.1.254"
#define LOCAL_PORT 12345

int main() {
    init_switch(PROG_NAME);
    init_bf_rt(PROG_NAME);
    init_ports(PORT_PATH);
    setup_arp_table();
    setup_dip_lookup_table();
    setup_offload_connection_table();
    setup_dest_to_egress_port_table();
    setup_d_index_to_egress_port_table();
    setup_lb_index_to_egress_port_table();
    setup_d_index_to_ip_port_table();
    init_controller(LOCAL_IP, LOCAL_PORT, RULE_PATH, D_INDEX_PATH, V_INFO_PATH);
    FILE *arp_table_file = fopen(ARP_TABLE_PATH, "r");
    if (arp_table_file == NULL) {
        printf("Failed to open arp_table_file\n");
        exit(1);
    }
    fseek(arp_table_file, 0, SEEK_END);
    long arp_table_file_size = ftell(arp_table_file);
    fseek(arp_table_file, 0, SEEK_SET);
    char *arp_table_json = (char *)malloc(arp_table_file_size + 1);
    fread(arp_table_json, 1, arp_table_file_size, arp_table_file);
    fclose(arp_table_file);
    arp_table_json[arp_table_file_size] = '\0';
    cJSON *arp_table_array = cJSON_Parse(arp_table_json);
    if (arp_table_array == NULL) {
        perror("cJSON_Parse failed");
        exit(1);
    }
    int arp_table_size = cJSON_GetArraySize(arp_table_array);
    arp_table_entry_t arp_table_entry[arp_table_size];
    for (int i = 0; i < arp_table_size; i++) {
        cJSON *arp_table = cJSON_GetArrayItem(arp_table_array, i);
        cJSON *opcode = cJSON_GetObjectItem(arp_table, "opcode");
        cJSON *target_proto_addr = cJSON_GetObjectItem(arp_table, "target_proto_addr");
        cJSON *arp_mac_prefix = cJSON_GetObjectItem(arp_table, "mac_prefix");
        cJSON *arp_mac_suffix = cJSON_GetObjectItem(arp_table, "mac_suffix");
        arp_table_entry[i].opcode = opcode->valueint;
        arp_table_entry[i].target_proto_addr = target_proto_addr->valueint;
        arp_table_entry[i].arp_mac = ((uint64_t)arp_mac_prefix->valueint << 24) + (uint64_t)arp_mac_suffix->valueint;
    }
    add_arp_table_entry(arp_table_size, arp_table_entry);
    cJSON_Delete(arp_table_array);
    free(arp_table_json);
    FILE *d_index_file = fopen(D_INDEX_PATH, "r");
    if (d_index_file == NULL) {
        printf("Failed to open d_index_file\n");
        exit(1);
    }
    fseek(d_index_file, 0, SEEK_END);
    long d_index_file_size = ftell(d_index_file);
    fseek(d_index_file, 0, SEEK_SET);
    char *d_index_json = (char *)malloc(d_index_file_size + 1);
    fread(d_index_json, 1, d_index_file_size, d_index_file);
    fclose(d_index_file);
    d_index_json[d_index_file_size] = '\0';
    cJSON *d_index_array = cJSON_Parse(d_index_json);
    if (d_index_array == NULL) {
        perror("cJSON_Parse failed");
        exit(1);
    }
    int d_index_size = cJSON_GetArraySize(d_index_array);
    d_index_to_egress_port_table_entry_t *d_index_to_egress_port_table_entry = (d_index_to_egress_port_table_entry_t *)malloc
                                                                               (sizeof(d_index_to_egress_port_table_entry_t) * d_index_size);
    d_index_to_ip_port_table_entry_t *d_index_to_ip_port_table_entry = (d_index_to_ip_port_table_entry_t *)malloc
                                                                       (sizeof(d_index_to_ip_port_table_entry_t) * d_index_size);
    dip_lookup_table_entry_t *dip_lookup_table_entry = (dip_lookup_table_entry_t *)malloc
                                                       (sizeof(dip_lookup_table_entry_t) * d_index_size);
    for (int i = 0; i < d_index_size; i++) {
        cJSON *d_index_item = cJSON_GetArrayItem(d_index_array, i);
        cJSON *d_index = cJSON_GetObjectItem(d_index_item, "d_index");
        cJSON *ip = cJSON_GetObjectItem(d_index_item, "ip");
        cJSON *port = cJSON_GetObjectItem(d_index_item, "port");
        cJSON *mac_prefix = cJSON_GetObjectItem(d_index_item, "mac_prefix");
        cJSON *mac_suffix = cJSON_GetObjectItem(d_index_item, "mac_suffix");
        cJSON *egress_port = cJSON_GetObjectItem(d_index_item, "egress_port");
        d_index_to_egress_port_table_entry[i].d_index = d_index->valueint;
        d_index_to_egress_port_table_entry[i].dst_mac = ((uint64_t)mac_prefix->valueint << 24) + (uint64_t)mac_suffix->valueint;
        d_index_to_egress_port_table_entry[i].dst_port = egress_port->valueint;
        d_index_to_ip_port_table_entry[i].d_index = d_index->valueint;
        d_index_to_ip_port_table_entry[i].dst_ip = ip->valueint;
        d_index_to_ip_port_table_entry[i].dst_port = port->valueint;
        dip_lookup_table_entry[i].src_ip = ip->valueint;
        dip_lookup_table_entry[i].src_port = port->valueint;
    }
    add_dip_lookup_table_entry(d_index_size, dip_lookup_table_entry);
    add_d_index_to_egress_port_table_entry(d_index_size, d_index_to_egress_port_table_entry);
    add_d_index_to_ip_port_table_entry(d_index_size, d_index_to_ip_port_table_entry);
    cJSON_Delete(d_index_array);
    free(d_index_json);
    free(dip_lookup_table_entry);
    free(d_index_to_egress_port_table_entry);
    free(d_index_to_ip_port_table_entry);
    FILE *lb_index_file = fopen(LB_INDEX_PATH, "r");
    if (lb_index_file == NULL) {
        printf("Failed to open lb_index_file\n");
        exit(1);
    }
    fseek(lb_index_file, 0, SEEK_END);
    long lb_index_file_size = ftell(lb_index_file);
    fseek(lb_index_file, 0, SEEK_SET);
    char *lb_index_json = (char *)malloc(lb_index_file_size + 1);
    fread(lb_index_json, 1, lb_index_file_size, lb_index_file);
    fclose(lb_index_file);
    lb_index_json[lb_index_file_size] = '\0';
    cJSON *lb_index_array = cJSON_Parse(lb_index_json);
    if (lb_index_array == NULL) {
        perror("cJSON_Parse failed");
        exit(1);
    }
    int lb_index_size = cJSON_GetArraySize(lb_index_array);
    lb_index_to_egress_port_table_entry_t *lb_index_to_egress_port_table_entry = (lb_index_to_egress_port_table_entry_t *)malloc
                                                                                 (sizeof(lb_index_to_egress_port_table_entry_t) * lb_index_size);
    for (int i = 0; i < lb_index_size; i++) {
        cJSON *lb_index_item = cJSON_GetArrayItem(lb_index_array, i);
        cJSON *lb_index = cJSON_GetObjectItem(lb_index_item, "lb_index");
        cJSON *mac_prefix = cJSON_GetObjectItem(lb_index_item, "mac_prefix");
        cJSON *mac_suffix = cJSON_GetObjectItem(lb_index_item, "mac_suffix");
        cJSON *egress_port = cJSON_GetObjectItem(lb_index_item, "egress_port");
        lb_index_to_egress_port_table_entry[i].lb_index = lb_index->valueint;
        lb_index_to_egress_port_table_entry[i].dst_mac = ((uint64_t)mac_prefix->valueint << 24) + (uint64_t)mac_suffix->valueint;
        lb_index_to_egress_port_table_entry[i].dst_port = egress_port->valueint;
    }
    add_lb_index_to_egress_port_table_entry(lb_index_size, lb_index_to_egress_port_table_entry);
    cJSON_Delete(lb_index_array);
    free(lb_index_json);
    FILE *dest_to_egress_file = fopen(DEST_TO_EGRESS_PATH, "r");
    if (dest_to_egress_file == NULL) {
        printf("Failed to open dest_to_egress_file\n");
        exit(1);
    }
    fseek(dest_to_egress_file, 0, SEEK_END);
    long dest_to_egress_file_size = ftell(dest_to_egress_file);
    fseek(dest_to_egress_file, 0, SEEK_SET);
    char *dest_to_egress_json = (char *)malloc(dest_to_egress_file_size + 1);
    fread(dest_to_egress_json, 1, dest_to_egress_file_size, dest_to_egress_file);
    fclose(dest_to_egress_file);
    dest_to_egress_json[dest_to_egress_file_size] = '\0';
    cJSON *dest_to_egress_array = cJSON_Parse(dest_to_egress_json);
    if (dest_to_egress_array == NULL) {
        perror("cJSON_Parse failed");
        exit(1);
    }
    int dest_to_egress_size = cJSON_GetArraySize(dest_to_egress_array);
    dest_to_egress_port_table_entry_t dest_to_egress_port_table_entry[dest_to_egress_size];
    for (int i = 0; i < dest_to_egress_size; i++) {
        cJSON *dest_to_egress_item = cJSON_GetArrayItem(dest_to_egress_array, i);
        cJSON *dst_addr = cJSON_GetObjectItem(dest_to_egress_item, "dst_addr");
        cJSON *prefix_len = cJSON_GetObjectItem(dest_to_egress_item, "prefix_len");
        cJSON *src_mac_prefix = cJSON_GetObjectItem(dest_to_egress_item, "src_mac");
        cJSON *src_mac_suffix = cJSON_GetObjectItem(dest_to_egress_item, "src_mac_suffix");
        cJSON *dst_mac_prefix = cJSON_GetObjectItem(dest_to_egress_item, "dst_mac");
        cJSON *dst_mac_suffix = cJSON_GetObjectItem(dest_to_egress_item, "dst_mac_suffix");
        cJSON *dst_port = cJSON_GetObjectItem(dest_to_egress_item, "egress_port");
        dest_to_egress_port_table_entry[i].dst_addr = dst_addr->valueint;
        dest_to_egress_port_table_entry[i].prefix_len = prefix_len->valueint;
        dest_to_egress_port_table_entry[i].src_mac = ((uint64_t)src_mac_prefix->valueint << 24) + (uint64_t)src_mac_suffix->valueint;
        dest_to_egress_port_table_entry[i].dst_mac = ((uint64_t)dst_mac_prefix->valueint << 24) + (uint64_t)dst_mac_suffix->valueint;
        dest_to_egress_port_table_entry[i].dst_port = dst_port->valueint;
    }
    add_dest_to_egress_port_table_entry(dest_to_egress_size, dest_to_egress_port_table_entry);
    cJSON_Delete(dest_to_egress_array);
    free(dest_to_egress_json);
    run_controller();
}