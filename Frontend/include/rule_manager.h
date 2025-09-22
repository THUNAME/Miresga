#ifndef RULE_MANAGER_H_
#define RULE_MANAGER_H_

#include "fmt/format.h"
#include "fmt/ranges.h"
#include "spdlog/spdlog.h"
#include "miresga_utils.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <memory>
#include <string>
#include <arpa/inet.h>
#include <unordered_map>

struct RuleEntry_t {
    uint8_t offload_flag;
    uint8_t d_index;
};

typedef std::unordered_map<std::string, RuleEntry_t*> RuleTable_t;
typedef std::unordered_map<uint8_t, ServerInfo_t*> BackendServerInfoTable_t;

class RuleManager
{
private:
    RuleTable_t _rule_table;
    BackendServerInfoTable_t _backend_server_info_table;
    ServerInfo_t* _virtual_server_info;
    inline static RuleManager* _instance = nullptr;
    RuleManager();
    ~RuleManager();
public:
    static RuleManager* get_instance();
    static void destroy_instance();
    MiresgaStatus_t add_rule(std::string host_name, RuleEntry_t* rule);
    MiresgaStatus_t remove_rule(std::string host_name);
    MiresgaStatus_t get_rule(std::string host_name, RuleEntry_t** rule);
    MiresgaStatus_t add_rule(char* host_name, RuleEntry_t* rule);
    MiresgaStatus_t remove_rule(char* host_name);
    MiresgaStatus_t get_rule(char* host_name, RuleEntry_t** rule);
    MiresgaStatus_t add_backend_server_info(uint8_t d_index, ServerInfo_t* server_info);
    MiresgaStatus_t remove_backend_server_info(uint8_t d_index);
    MiresgaStatus_t get_backend_server_info(uint8_t d_index, ServerInfo_t** server_info);
    MiresgaStatus_t set_virtual_server_info(ServerInfo_t* server_info);
    MiresgaStatus_t get_virtual_server_info(ServerInfo_t** server_info);
};

#endif