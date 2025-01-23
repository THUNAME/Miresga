#ifndef RULE_CONTROLLER_HPP_
#define RULE_CONTROLLER_HPP_

#include "my_config.hpp"
#include "flow_data.hpp"
#include <string>
#include <shared_mutex>
#include <unordered_map>

extern "C" {
    #include <rte_ether.h>
}

class server_info_t {
public:
    rte_ether_addr mac;
    uint32_t ip;
    uint16_t port;
    server_info_t();
    server_info_t(rte_ether_addr mac, uint32_t ip, uint16_t port);
    server_info_t(const server_info_t& server_info);
};

class rule_controller_t {
private:
    std::unordered_map<std::string, my_data_t *> rule_map;
    std::unordered_map<uint8_t, server_info_t *> d_index_map;
    server_info_t *virtual_server_info;
    std::shared_mutex rule_map_mutex;
    std::shared_mutex d_index_map_mutex;
    std::shared_mutex virtual_server_info_mutex;
public:
    rule_controller_t();
    status_t add_balancing_rule(char* host_name, my_data_t *data);
    my_data_t * lookup_balancing_rule(char* key);
    status_t del_balancing_rule(char* key);
    status_t add_d_index_rule(uint8_t index, server_info_t *server_info);
    server_info_t * lookup_backend_server_info(uint8_t index);
    status_t del_d_index_rule(uint8_t index);
    status_t update_virtual_server_info(server_info_t *new_virtual_server_info);
    server_info_t * get_virtual_server_info();
};

#endif