#ifndef FLOW_DATA_HPP
#define FLOW_DATA_HPP

#include <iostream>
extern "C" {
    #include <rte_malloc.h>
}


class my_key_t {
public:
    uint8_t crc;
    uint32_t client_ip;
    uint16_t client_port;
};

class my_data_t {
public:
    uint8_t offload_flag;
    uint8_t d_index;
};

class my_hash_pair_t {
public:
    uint64_t key;
    my_data_t data;
};

class my_pair_t {
public:
    my_key_t key;
    my_data_t data;
};

enum flow_state {
    INIT,
    BACKEND_SYN,
    OFFLOAD,
    COMPLETE,
};

class flow_data_t {
public:
    flow_state state;
    my_data_t entry_data;
    char *recv_pkt;
    size_t pkt_size;
    flow_data_t() {
        state = INIT;
        recv_pkt = nullptr;
        pkt_size = 0;
    }
    ~flow_data_t() {
        if (recv_pkt != nullptr) {
            rte_free(recv_pkt);
        }
    }
};

#endif