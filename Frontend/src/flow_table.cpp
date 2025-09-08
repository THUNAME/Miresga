#include "flow_table.h"

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

void FlowTable::insert_flow(MiresgaOFTKey_t& key, MiresgaFlowData_t* flow_data) {
    _flow_map[key.crc].emplace(packed_key(key), flow_data);
}

MiresgaFlowData_t* FlowTable::get_flow(MiresgaOFTKey_t& key) {
    MiresgaFlowData_t* res = nullptr;
    _flow_map[key.crc].visit(packed_key(key), [&res](const auto& item) {
        res = item.second;
    });
    return res;
}

void FlowTable::remove_flow(MiresgaOFTKey_t& key) {
    _flow_map[key.crc].visit(packed_key(key), [](const auto& item) {
        delete item.second;
    });
    _flow_map[key.crc].erase(packed_key(key));
}

std::vector<MiresgaOFTEntry_t> FlowTable::get_crc_entries(uint8_t crc) {
    std::vector<MiresgaOFTEntry_t> res;
    _flow_map[crc].visit_all([&res](const auto& item) {
        res.push_back(item.second->entry_data);
    });
    return res;
}