#include "rule_manager.h"

static auto logger = spdlog::stdout_color_mt("RuleManager");

RuleManager::RuleManager() {
    _virtual_server_info = new ServerInfo_t;
}

RuleManager::~RuleManager() {
    for (auto it = _rule_table.begin(); it != _rule_table.end(); ++it) {
        delete it->second;
    }
    for (auto it = _backend_server_info_table.begin(); it != _backend_server_info_table.end(); ++it) {
        delete it->second;
    }
    delete _virtual_server_info;
}

RuleManager* RuleManager::get_instance() {
    if (_instance == nullptr) {
        SPDLOG_LOGGER_INFO(logger, "Creating RuleManager instance");
        _instance = new RuleManager();
    }
    return _instance;
}

void RuleManager::destroy_instance() {
    if (_instance != nullptr) {
        SPDLOG_LOGGER_WARN(logger, "Destroying RuleManager instance");
        delete _instance;
        _instance = nullptr;
    }
}

__attribute__((always_inline)) MiresgaStatus_t RuleManager::add_rule(std::string host_name, RuleEntry_t* rule) {
    if (unlikely(host_name.empty() || rule == nullptr)) {
        SPDLOG_LOGGER_ERROR(logger, "Empty host name or null rule");
        return INVALID_PARAMETER;
    }
    SPDLOG_LOGGER_DEBUG(logger, "Adding rule for host: {}", host_name);
    _rule_table[host_name] = rule;
    return OK;
}

__attribute__((always_inline)) MiresgaStatus_t RuleManager::remove_rule(std::string host_name) {
    if (unlikely(host_name.empty())) {
        SPDLOG_LOGGER_ERROR(logger, "Empty host name");
        return INVALID_PARAMETER;
    }
    auto it = _rule_table.find(host_name);
    if (likely(it != _rule_table.end())) {
        delete it->second;
        _rule_table.erase(it);
        SPDLOG_LOGGER_DEBUG(logger, "Removed rule for host: {}", host_name);
        return OK;
    }
    SPDLOG_LOGGER_ERROR(logger, "No rule found for host: {}", host_name);
    return OUT_OF_RANGE;
}

__attribute__((always_inline)) MiresgaStatus_t RuleManager::get_rule(std::string host_name, RuleEntry_t** rule) {
    if (unlikely(host_name.empty() || rule == nullptr)) {
        SPDLOG_LOGGER_ERROR(logger, "Empty host name or null rule");
        return INVALID_PARAMETER;
    }
    auto it = _rule_table.find(host_name);
    if (likely(it != _rule_table.end())) {
        SPDLOG_LOGGER_DEBUG(logger, "Found rule for host: {}", host_name);
        *rule = it->second;
        return OK;
    }
    *rule = nullptr;
    SPDLOG_LOGGER_ERROR(logger, "No rule found for host: {}", host_name);
    return OUT_OF_RANGE;
}

__attribute__((always_inline)) MiresgaStatus_t RuleManager::add_rule(char* host_name, RuleEntry_t* rule) {
    if (unlikely(host_name == nullptr || rule == nullptr)) {
        SPDLOG_LOGGER_ERROR(logger, "Null host name or rule");
        return INVALID_PARAMETER;
    }
    std::string key(host_name);
    SPDLOG_LOGGER_DEBUG(logger, "Adding rule for host: {}", key);
    _rule_table[key] = rule;
    return OK;
}

__attribute__((always_inline)) MiresgaStatus_t RuleManager::remove_rule(char* host_name) {
    if (unlikely(host_name == nullptr)) {
        SPDLOG_LOGGER_ERROR(logger, "Null host name");
        return INVALID_PARAMETER;
    }
    std::string key(host_name);
    auto it = _rule_table.find(key);
    if (likely(it != _rule_table.end())) {
        delete it->second;
        _rule_table.erase(it);
        SPDLOG_LOGGER_DEBUG(logger, "Removed rule for host: {}", key);
        return OK;
    }
    SPDLOG_LOGGER_ERROR(logger, "No rule found for host: {}", key);
    return OUT_OF_RANGE;
}

__attribute__((always_inline)) MiresgaStatus_t RuleManager::get_rule(char* host_name, RuleEntry_t** rule) {
    if (unlikely(host_name == nullptr || rule == nullptr)) {
        SPDLOG_LOGGER_ERROR(logger, "Null host name or rule");
        return INVALID_PARAMETER;
    }
    std::string key(host_name);
    auto it = _rule_table.find(key);
    if (likely(it != _rule_table.end())) {
        SPDLOG_LOGGER_DEBUG(logger, "Found rule for host: {}", key);
        *rule = it->second;
        return OK;
    }
    SPDLOG_LOGGER_ERROR(logger, "No rule found for host: {}", key);
    *rule = nullptr;
    return OUT_OF_RANGE;
}

__attribute__((always_inline)) MiresgaStatus_t RuleManager::add_backend_server_info(uint8_t d_index, ServerInfo_t* server_info) {
    if (unlikely(server_info == nullptr)) {
        SPDLOG_LOGGER_ERROR(logger, "Null server info");
        return INVALID_PARAMETER;
    }
    SPDLOG_LOGGER_DEBUG(logger, "Adding backend server info for d_index: {}", d_index);
    SPDLOG_LOGGER_DEBUG(logger, "Server Info - MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, IP: {}, Port: {}",
                        server_info->mac.addr_bytes[0], server_info->mac.addr_bytes[1],
                        server_info->mac.addr_bytes[2], server_info->mac.addr_bytes[3],
                        server_info->mac.addr_bytes[4], server_info->mac.addr_bytes[5],
                        server_info->ip, server_info->port);
    _backend_server_info_table[d_index] = server_info;
    return OK;
}

__attribute__((always_inline)) MiresgaStatus_t RuleManager::remove_backend_server_info(uint8_t d_index) {
    auto it = _backend_server_info_table.find(d_index);
    if (likely(it != _backend_server_info_table.end())) {
        SPDLOG_LOGGER_DEBUG(logger, "Removing backend server info for d_index: {}", d_index);
        delete it->second;
        _backend_server_info_table.erase(it);
        return OK;
    }
    SPDLOG_LOGGER_ERROR(logger, "No backend server info found for d_index: {}", d_index);
    return OUT_OF_RANGE;
}

__attribute__((always_inline)) MiresgaStatus_t RuleManager::get_backend_server_info(uint8_t d_index, ServerInfo_t** server_info) {
    if (unlikely(server_info == nullptr)) {
        SPDLOG_LOGGER_ERROR(logger, "Null server info");
        return INVALID_PARAMETER;
    }
    auto it = _backend_server_info_table.find(d_index);
    if (likely(it != _backend_server_info_table.end())) {
        SPDLOG_LOGGER_DEBUG(logger, "Found backend server info for d_index: {}", d_index);
        *server_info = it->second;
        return OK;
    }
    *server_info = nullptr;
    SPDLOG_LOGGER_ERROR(logger, "No backend server info found for d_index: {}", d_index);
    return OUT_OF_RANGE;
}

__attribute__((always_inline)) MiresgaStatus_t RuleManager::set_virtual_server_info(ServerInfo_t* server_info) {
    if (unlikely(server_info == nullptr)) {
        SPDLOG_LOGGER_ERROR(logger, "Null server info");
        return INVALID_PARAMETER;
    }
    memcpy(_virtual_server_info, server_info, sizeof(ServerInfo_t));
    #ifdef DEBUG
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(_virtual_server_info->ip), ip_str, INET_ADDRSTRLEN);
    SPDLOG_LOGGER_DEBUG(logger, "Set virtual server info - MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, IP: {}, Port: {}",
                        _virtual_server_info->mac.addr_bytes[0], _virtual_server_info->mac.addr_bytes[1],
                        _virtual_server_info->mac.addr_bytes[2], _virtual_server_info->mac.addr_bytes[3],
                        _virtual_server_info->mac.addr_bytes[4], _virtual_server_info->mac.addr_bytes[5],
                        ip_str, ntohs(_virtual_server_info->port));
    #endif
    return OK;
}

__attribute__((always_inline)) MiresgaStatus_t RuleManager::get_virtual_server_info(ServerInfo_t** server_info) {
    if (unlikely(server_info == nullptr)) {
        SPDLOG_LOGGER_ERROR(logger, "Null server info");
        return INVALID_PARAMETER;
    }
    *server_info = _virtual_server_info;
    return OK;
}
