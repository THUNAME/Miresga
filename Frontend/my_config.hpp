#ifndef MY_CONFIG_HPP_
#define MY_CONFIG_HPP_
#define _GNU_SOURCE
//#define DEBUG
#define CONFIG_PATH "../config/config.json"
#define DPDK_CONFIG_PATH "../config/dpdk.json"

enum status_t {
    OK = 0,
    INTERNAL_ERROR,
    INVALID_PARAMETER,
    BUSYING, 
    OUT_OF_RANGE,
    UNKNOWN
};

enum operation_type_t {
    UPDATE_RULE,
    UPDATE_D_INDEX,
    UPDATE_V_INFO,
    OFFLOAD_ENTRIES
};

#endif