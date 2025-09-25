#include "flow_table.h"

static auto logger = spdlog::stdout_color_mt("flow_table");

FlowTable::FlowTable() {
    for (int i = 0; i < 256; ++i)
        _flow_map[i].reserve(DEFAULT_FLOW_MAP_SIZE);
}

FlowTable::~FlowTable() {
    for (int i = 0; i < 256; ++i) {
        _flow_map[i].visit_all([](const auto& item) {
            delete item.second;
        });
        _flow_map[i].clear();
    }
}

FlowTable* FlowTable::get_instance() {
    if (_instance == nullptr) {
        _instance = new FlowTable();
    }
    return _instance;
}

void FlowTable::destroy_instance() {
    if (_instance != nullptr) {
        delete _instance;
        _instance = nullptr;
    }
}

__attribute__((always_inline)) void FlowTable::insert_flow(MiresgaOFTKey_t& key, MiresgaFlowData_t* flow_data) {
    #ifdef DEBUG
    char ip_str[INET_ADDRSTRLEN];
    SPDLOG_LOGGER_DEBUG(logger, "Insert flow: key={}:{}", inet_ntop(AF_INET, &key.client_ip, ip_str, INET_ADDRSTRLEN), key.client_port);
    SPDLOG_LOGGER_DEBUG(logger, "Data: state={}", static_cast<int>(flow_data->state));
    #endif
    _flow_map[key.crc].emplace(packed_key(key), flow_data);
}

__attribute__((always_inline)) MiresgaFlowData_t* FlowTable::get_flow(MiresgaOFTKey_t& key) {
    MiresgaFlowData_t* res = nullptr;
    _flow_map[key.crc].visit(packed_key(key), [&](const auto& item) {
        #ifdef DEBUG
        char ip_str[INET_ADDRSTRLEN];
        SPDLOG_LOGGER_DEBUG(logger, "Get flow: key={}:{} state:{}", inet_ntop(AF_INET, &key.client_ip, ip_str, INET_ADDRSTRLEN), key.client_port, static_cast<int>(item.second->state));
        #endif
        res = item.second;
    });
    return res;
}

__attribute__((always_inline)) void FlowTable::remove_flow(MiresgaOFTKey_t& key) {
    _flow_map[key.crc].visit(packed_key(key), [&](const auto& item) {
        #ifdef DEBUG
        char ip_str[INET_ADDRSTRLEN];
        SPDLOG_LOGGER_DEBUG(logger, "Remove flow: key={}:{} state:{}", inet_ntop(AF_INET, &key.client_ip, ip_str, INET_ADDRSTRLEN), key.client_port, static_cast<int>(item.second->state));
        #endif
        delete item.second;
    });
    _flow_map[key.crc].erase(packed_key(key));
}

__attribute__((always_inline)) std::vector<MiresgaOFTEntry_t> FlowTable::get_crc_entries(uint8_t crc) {
    std::vector<MiresgaOFTEntry_t> res;
    // Do not lock the map. Otherwise this function may block the packet processor threads.
    _flow_map[crc].visit_all([&res](const auto& item) {
        res.push_back(item.second->entry_data);
    });
    return res;
}