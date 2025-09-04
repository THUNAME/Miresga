#include "rule_manager.h"

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
        _instance = new RuleManager();
    }
    return _instance;
}

void RuleManager::destroy_instance() {
    if (_instance != nullptr) {
        delete _instance;
        _instance = nullptr;
    }
}

MiresgaStatus_t RuleManager::add_rule(std::string host_name, RuleEntry_t* rule) {
    if (host_name.empty() || rule == nullptr) {
        return INVALID_PARAMETER;
    }
    _rule_table[host_name] = rule;
    return OK;
}

MiresgaStatus_t RuleManager::remove_rule(std::string host_name) {
    if (host_name.empty()) {
        return INVALID_PARAMETER;
    }
    auto it = _rule_table.find(host_name);
    if (it != _rule_table.end()) {
        delete it->second;
        _rule_table.erase(it);
        return OK;
    }
    return OUT_OF_RANGE;
}

MiresgaStatus_t RuleManager::get_rule(std::string host_name, RuleEntry_t** rule) {
    if (host_name.empty() || rule == nullptr) {
        return INVALID_PARAMETER;
    }
    auto it = _rule_table.find(host_name);
    if (it != _rule_table.end()) {
        *rule = it->second;
        return OK;
    }
    *rule = nullptr;
    return OUT_OF_RANGE;
}

MiresgaStatus_t RuleManager::add_rule(char* host_name, RuleEntry_t* rule) {
    if (host_name == nullptr || rule == nullptr) {
        return INVALID_PARAMETER;
    }
    std::string key(host_name);
    _rule_table[key] = rule;
    return OK;
}

MiresgaStatus_t RuleManager::remove_rule(char* host_name) {
    if (host_name == nullptr) {
        return INVALID_PARAMETER;
    }
    std::string key(host_name);
    auto it = _rule_table.find(key);
    if (it != _rule_table.end()) {
        delete it->second;
        _rule_table.erase(it);
        return OK;
    }
    return OUT_OF_RANGE;
}

MiresgaStatus_t RuleManager::get_rule(char* host_name, RuleEntry_t** rule) {
    if (host_name == nullptr || rule == nullptr) {
        return INVALID_PARAMETER;
    }
    std::string key(host_name);
    auto it = _rule_table.find(key);
    if (it != _rule_table.end()) {
        *rule = it->second;
        return OK;
    }
    *rule = nullptr;
    return OUT_OF_RANGE;
}

MiresgaStatus_t RuleManager::add_backend_server_info(uint8_t d_index, ServerInfo_t* server_info) {
    if (server_info == nullptr) {
        return INVALID_PARAMETER;
    }
    _backend_server_info_table[d_index] = server_info;
    return OK;
}

MiresgaStatus_t RuleManager::remove_backend_server_info(uint8_t d_index) {
    auto it = _backend_server_info_table.find(d_index);
    if (it != _backend_server_info_table.end()) {
        delete it->second;
        _backend_server_info_table.erase(it);
        return OK;
    }
    return OUT_OF_RANGE;
}

MiresgaStatus_t RuleManager::get_backend_server_info(uint8_t d_index, ServerInfo_t** server_info) {
    if (server_info == nullptr) {
        return INVALID_PARAMETER;
    }
    auto it = _backend_server_info_table.find(d_index);
    if (it != _backend_server_info_table.end()) {
        *server_info = it->second;
        return OK;
    }
    *server_info = nullptr;
    return OUT_OF_RANGE;
}

MiresgaStatus_t RuleManager::set_virtual_server_info(ServerInfo_t* server_info) {
    if (server_info == nullptr) {
        return INVALID_PARAMETER;
    }
    memcpy(_virtual_server_info, server_info, sizeof(ServerInfo_t));
    return OK;
}

MiresgaStatus_t RuleManager::get_virtual_server_info(ServerInfo_t** server_info) {
    if (server_info == nullptr) {
        return INVALID_PARAMETER;
    }
    *server_info = _virtual_server_info;
    return OK;
}
