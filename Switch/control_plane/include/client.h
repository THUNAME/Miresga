#ifndef CLIENT_H
#define CLIENT_H

#define CONFIG_DIR "../config/"

#include "tofino_wrapper.h"
#include "nlohmann/json.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <stdexcept>
#include <fstream>

struct MiresgaOFTKey_t
{
    uint8_t  modify_flag;
    uint8_t  crc;
    uint32_t client_ip;
    uint16_t client_port;
};

extern uint64_t packed_key(const MiresgaOFTKey_t key);

struct MiresgaOFTData_t
{
    uint8_t flow_state;
    uint8_t d_index;
};

struct MiresgaOFTEntry_t
{
    MiresgaOFTKey_t  key;
    MiresgaOFTData_t data;
};

struct EgressPortEntry_t {
    uint64_t src_mac;
    uint64_t dst_mac;
    uint64_t dst_port;
};

class SwitchClient_t {
private:
    inline static SwitchClient_t* _instance = nullptr;
    SwitchInfo_t* _switch_info;
    TableInfo_t* _arp_table;
    TableInfo_t* _dip_lookup_table;
    TableInfo_t* _offload_connection_table;
    TableInfo_t* _dest_to_egress_port_table;
    TableInfo_t* _d_index_to_egress_port_table;
    TableInfo_t* _lb_index_to_egress_port_table_0;
    TableInfo_t* _lb_index_to_egress_port_table_1;
    TableInfo_t* _d_index_to_ip_port_table;
    RegisterInfo_t* _updating_flag_reg;
    RegisterInfo_t* _new_tb_idx_reg;
    RegisterInfo_t* _bloom_filter_reg_1;
    RegisterInfo_t* _bloom_filter_reg_2;
    uint8_t _new_tb_idx;
    static uint64_t _parse_value(const nlohmann::json& value_json);
    static std::vector<KeyInput_t> _parse_keys(const nlohmann::json& key_json);
    static TableInfo_t* _init_table_from_config(std::string config_path);
    SwitchClient_t(std::string config_dir=CONFIG_DIR);
    ~SwitchClient_t();
public:
    static void init_client(std::string config_dir=CONFIG_DIR);
    static SwitchClient_t* get_instance();
    void add_offload_entries(std::vector<MiresgaOFTEntry_t> entries);
    void del_offload_entries(std::vector<MiresgaOFTKey_t> keys);
    void start_updating(std::unordered_map<uint8_t, EgressPortEntry_t> new_crc_2_idx);
    void finish_updating();
};

#endif // CLIENT_H