#ifndef TOFINO_WRAPPER_H_
#define TOFINO_WRAPPER_H_

extern "C" {
    #include <bf_rt/bf_rt_init.h>
    #include <bf_pm/bf_pm_intf.h>
    #include <bf_rt/bf_rt_table.h>
    #include <mc_mgr/mc_mgr_intf.h>
    #include <bf_rt/bf_rt_session.h>
    #include <bf_switchd/bf_switchd.h>
    #include <bf_rt/bf_rt_table_key.h>
    #include <bf_rt/bf_rt_table_data.h>
    #include <tofino/pdfixed/pd_mirror.h>
    #include <bfsys/bf_sal/bf_sys_timer.h>
    #include <tofino/pdfixed/pd_conn_mgr.h>
}

#include <vector>
#include <string>
#include <stdexcept>
#include <unordered_map>

#include "fmt/format.h"
#include "fmt/ranges.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#define MAX_BATCH_SIZE 64

struct PortInfo_t {
    std::string port_name;
    bf_port_speed_t port_speed;
    bf_fec_type_t fec_type;
};

class SwitchInfo_t {
private:
    inline static SwitchInfo_t* _instance = nullptr;
    std::string _prog_name;
    const bf_rt_info_hdl* _bf_rt_info;
    bf_rt_session_hdl* _session;
    bf_rt_target_t* _dev_tgt;
    bf_switchd_context_t* _switchd_ctx;
    SwitchInfo_t(std::string prog_name);
    ~SwitchInfo_t();
public:
    static void init_switch(std::string prog_name);
    static SwitchInfo_t* get_instance();
    void init_ports(std::vector<PortInfo_t> port_info_list);
    const bf_rt_table_hdl* get_table_hdl(std::string table_name);
    void add_batched_entry(const bf_rt_table_hdl* table_hdl,
                           std::vector<bf_rt_table_key_hdl*> key_hdls,
                           std::vector<bf_rt_table_data_hdl*> data_hdls,
                           size_t size);
    void delete_batched_entry(const bf_rt_table_hdl* table_hdl,
                              std::vector<bf_rt_table_key_hdl*> key_hdls,
                              size_t size);
    void modify_batched_entry(const bf_rt_table_hdl* table_hdl,
                              std::vector<bf_rt_table_key_hdl*> key_hdls,
                              std::vector<bf_rt_table_data_hdl*> data_hdls,
                              size_t size);
    void add_entry(const bf_rt_table_hdl* table_hdl,
                   bf_rt_table_key_hdl* key_hdl,
                   bf_rt_table_data_hdl* data_hdl);
    void delete_entry(const bf_rt_table_hdl* table_hdl,
                      bf_rt_table_key_hdl* key_hdl);
    void modify_entry(const bf_rt_table_hdl* table_hdl,
                      bf_rt_table_key_hdl* key_hdl,
                      bf_rt_table_data_hdl* data_hdl);  
    void clear_table(const bf_rt_table_hdl* table_hdl);
};

class KeyInput_t {
public:
    std::string name;
    uint64_t value;
    KeyInput_t(std::string name, uint64_t value):name(name), value(value){};
};

typedef KeyInput_t ExactKeyInput_t;
typedef KeyInput_t DataInput_t;

class LPMKeyInput_t : public KeyInput_t {
public:
    uint32_t prefix_len;
    LPMKeyInput_t(std::string name, uint64_t value, uint32_t prefix_len):
        KeyInput_t(name, value), prefix_len(prefix_len) {};
};

class TernaryKeyInput_t : public KeyInput_t {
public:
    uint64_t mask;
    TernaryKeyInput_t(std::string name, uint64_t mask):
        KeyInput_t(name, 0), mask(mask) {};
};

class RangeKeyInput_t : public KeyInput_t {
public:
    uint64_t start;
    uint64_t end;
    RangeKeyInput_t(std::string name, uint64_t start, uint64_t end):
        KeyInput_t(name, 0), start(start), end(end) {};
};

class TableInfo_t {
private:
    SwitchInfo_t* _switch_info;
    const bf_rt_table_hdl* _table_hdl;
    std::vector<bf_rt_table_key_hdl*> _key_hdls;
    std::vector<bf_rt_table_data_hdl*> _data_hdls;
    std::unordered_map<std::string, std::pair<bf_rt_id_t, bf_rt_key_field_type_t>> _key_name_2_id_map;
    std::unordered_map<std::string, bf_rt_id_t> _data_name_2_id_map;
    std::unordered_map<std::string, bf_rt_id_t> _action_name_2_id_map;
    bool _enable_batch;
public:
    TableInfo_t(std::string table_name, std::vector<std::pair<std::string, bf_rt_key_field_type_t>> key_names,
                std::unordered_map<std::string, std::vector<std::string>> action_name_to_data_names, bool enable_batch=false);
    ~TableInfo_t();
    void add_entry(std::vector<std::vector<KeyInput_t>> key_field_values,
                   std::string action_name,
                   std::vector<std::vector<DataInput_t>> data_field_values);
    void delete_entry(std::vector<std::vector<KeyInput_t>> key_field_values);
    void modify_entry(std::vector<std::vector<KeyInput_t>> key_field_values,
                      std::string action_name,
                      std::vector<std::vector<DataInput_t>> data_field_values);
    void clear_all_entry();
};

class RegisterInfo_t {
private:
    SwitchInfo_t* _switch_info;
    const bf_rt_table_hdl* _reg_hdl;
    bf_rt_table_key_hdl* _key_hdl;
    bf_rt_table_data_hdl* _data_hdl;
    bf_rt_id_t _index_id;
    bf_rt_id_t _data_id;
public:
    RegisterInfo_t(std::string reg_name);
    ~RegisterInfo_t();
    void write_reg(uint64_t index, uint64_t data);
    void clear_reg();
};

#endif