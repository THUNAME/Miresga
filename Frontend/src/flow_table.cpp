#include "flow_table.h"

FlowTable::FlowTable() {
    _flow_map.reserve(DEFAULT_FLOW_MAP_SIZE);
}

FlowTable::~FlowTable() {
    _flow_map.visit_all([](const auto& item) {
        delete item.second;
    });
    _flow_map.clear();
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

void FlowTable::insert_flow(uint64_t key, MiresgaFlowData_t* flow_data) {
    _flow_map.emplace(key, flow_data);
}

MiresgaFlowData_t* FlowTable::get_flow(uint64_t key) {
    MiresgaFlowData_t* res = nullptr;
    _flow_map.visit(key, [&res](const auto& item) {
        res = item.second;
    });
    return res;
}

void FlowTable::remove_flow(uint64_t key) {
    _flow_map.visit(key, [](const auto& item) {
        delete item.second;
    });
    _flow_map.erase(key);
}