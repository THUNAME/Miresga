#ifndef CONTROLLER_H_
#define CONTROLLER_H_
#include <sys/epoll.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "client.h"
#include <unistd.h>
#include <cJson/cJSON.h>

struct my_key_t {
    uint8_t crc;
    uint32_t client_ip;
    uint16_t client_port;
};

struct my_data_t {
    uint8_t offload_flag;
    uint8_t d_index;
};

struct my_pair_t {
    struct my_key_t key;
    struct my_data_t data;
};

struct rule_t {
    char rule[20];
    uint8_t d_index;
    uint8_t offload_flag;
};

struct server_info_t {
    uint8_t mac[6];
    uint32_t ip;
    uint16_t port;
};

struct d_index_t {
    uint8_t d_index;
    struct server_info_t server_info;
};

extern void init_controller(char *ip, uint16_t port, char *rule_json_path, 
                            char *d_index_json_path, char *v_info_json_path);
extern void run_controller();

#endif