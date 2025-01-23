#include "rule_controller.hpp"

using std::string;
using std::shared_mutex;
using std::shared_lock;
using std::unique_lock;

server_info_t::server_info_t() {
    memset(mac.addr_bytes, 0, sizeof(mac));
    ip = 0;
    port = 0;
}

server_info_t::server_info_t(rte_ether_addr mac, uint32_t ip, uint16_t port) {
    rte_ether_addr_copy(&mac, &this->mac);
    this->ip = ip;
    this->port = port;
}

server_info_t::server_info_t(const server_info_t& server_info) {
    rte_ether_addr_copy(&server_info.mac, &mac);
    ip = server_info.ip;
    port = server_info.port;
}

rule_controller_t::rule_controller_t() {
    virtual_server_info = new server_info_t;
}

status_t rule_controller_t::add_balancing_rule(char* key, my_data_t *data) {
    string str_key(key);
    unique_lock<shared_mutex> lock(rule_map_mutex);
    rule_map[str_key] = data;
    return OK;
}

my_data_t * rule_controller_t::lookup_balancing_rule(char* key) {
    string str_key(key);
    shared_lock<shared_mutex> lock(rule_map_mutex);
    auto res = rule_map.find(str_key);
    if(res == rule_map.end()) {
        return nullptr;
    }
    return res->second;
}

status_t rule_controller_t::del_balancing_rule(char* key) {
    string str_key(key);
    unique_lock<shared_mutex> lock(rule_map_mutex);
    auto res = rule_map.find(str_key);
    if(res == rule_map.end()){
        return INTERNAL_ERROR;
    }
    delete res->second;
    rule_map.erase(res);
    return OK;
}

status_t rule_controller_t::add_d_index_rule(uint8_t index, server_info_t * server_info) {
    unique_lock<shared_mutex> lock(d_index_map_mutex);
    d_index_map[index] = server_info;
    return OK;
}

server_info_t * rule_controller_t::lookup_backend_server_info(uint8_t index) {
    shared_lock<shared_mutex> lock(d_index_map_mutex);
    auto res = d_index_map.find(index);
    if(res == d_index_map.end()) {
        return nullptr;
    }
    return res->second;
}

status_t rule_controller_t::del_d_index_rule(uint8_t index) {
    unique_lock<shared_mutex> lock(d_index_map_mutex);
    auto res = d_index_map.find(index);
    if(res == d_index_map.end()) {
        return INTERNAL_ERROR;
    }
    delete res->second;
    d_index_map.erase(res);
    return OK;
}

status_t rule_controller_t::update_virtual_server_info(server_info_t * new_virtual_server_info) {
    unique_lock<shared_mutex> lock(virtual_server_info_mutex);
    memcpy(virtual_server_info, new_virtual_server_info, sizeof(server_info_t));
    return OK;
}

server_info_t * rule_controller_t::get_virtual_server_info() {
    return virtual_server_info;
}