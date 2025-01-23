#include <nlohmann/json.hpp>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <numa.h>
#include <iostream>
#include <fstream>
#include "pkt_processor.hpp"
#include "entry_controller.hpp"
#include "my_config.hpp"
#include "concurrentqueue/concurrentqueue.h"

using json = nlohmann::json;

int main(int argc, char *argv[]) {
    if(numa_available() == -1) {
        std::cerr << "NUMA is not available" << std::endl;
        return -1;
    }
    
    numa_set_bind_policy(1);
    numa_bind(numa_parse_nodestring("3"));

    std::ifstream total_config(CONFIG_PATH);
    json config;
    total_config >> config;
    std::string local_ip = config["local_ip"];
    uint32_t local_listen_port = config["local_listen_port"];
    uint32_t local_switch_port = config["local_switch_port"];
    std::string switch_ip = config["switch_ip"];
    uint32_t switch_port = config["switch_port"];
    std::vector<int> pkt_processor_core_ids;
    auto res = config["pkt_processor_core_ids"];
    if(res.is_array()) {
        int size = res.size();
        int i = 0;
        for(auto core_id : res) {
            if(i == size) {
                break;
            }
            pkt_processor_core_ids.push_back(core_id.get<int>());
            ++i;
        }
    }
    else if(!res.is_null()) {
        pkt_processor_core_ids.push_back(res.get<int>());
    }
    else {
        std::cerr << "pkt_processor_core_ids is not an array or an integer" << std::endl;
        return -1;
    }
    uint32_t memory_pool_size = config["memory_pool_size"];
    total_config.close();
    std::ifstream dpdk_config(DPDK_CONFIG_PATH);
    json dpdk_config_json;
    dpdk_config >> dpdk_config_json;
    dpdk_config_t dpdk_config_args;
    dpdk_config_args.pci_addr = (char *)dpdk_config_json["pci_addr"].get<std::string>().c_str();
    dpdk_config_args.rx_ring_size = dpdk_config_json["rx_ring_size"];
    dpdk_config_args.tx_ring_size = dpdk_config_json["tx_ring_size"];
    dpdk_config_args.num_mbufs = dpdk_config_json["num_mbufs"]; 
    dpdk_config_args.mbuf_cache_size = dpdk_config_json["mbuf_cache_size"]; 
    dpdk_config_args.mbuf_data_room_size = dpdk_config_json["mbuf_data_room_size"]; 
    dpdk_config_args.burst_size = dpdk_config_json["burst_size"];   
    dpdk_config_args.queue_size = pkt_processor_core_ids.size();
    std::cout << dpdk_config_args.queue_size << std::endl;
    dpdk_config.close();
    int epoll_fd = epoll_create1(0);
    if(epoll_fd == -1) {
        perror("epoll_create1");
        return -1;
    }
    std::cout << "Memory pool initializing" << std::endl;
    std::cout << "Memory pool initialized" << std::endl;
    libcuckoo::cuckoohash_map<uint64_t, flow_data_t *> flow_hash_map[256];
    std::cout << "Rule controller initializing" << std::endl;
    rule_controller_t *rule_controller = new rule_controller_t;
    std::cout << "Rule controller initialized" << std::endl;
    std::cout << "Entry controller initializing" << std::endl;
    moodycamel::ConcurrentQueue<my_pair_t> *add_queue = new moodycamel::ConcurrentQueue<my_pair_t>;
    moodycamel::ConcurrentQueue<my_key_t> *del_queue = new moodycamel::ConcurrentQueue<my_key_t>;
    std::shared_ptr<entry_controller_t> entry_controller = std::make_shared<entry_controller_t>(add_queue, del_queue);
    std::cout << "Entry controller initialized" << std::endl;
    std::cout << "Pkt processor initializing" << std::endl;
    pkt_processor_t::init_static_variable(argc, argv, &dpdk_config_args, rule_controller, add_queue, del_queue, flow_hash_map);
    std::vector<std::shared_ptr<pkt_processor_t>> pkt_processors;
    for(int i = 0; i < dpdk_config_args.queue_size; i++) {
        std::shared_ptr<pkt_processor_t> pkt_processor = std::make_shared<pkt_processor_t>(i);
        pkt_processors.push_back(pkt_processor);
    }
    std::cout << "Pkt processor initialized" << std::endl;
    sockaddr_in controller_addr, switch_addr;
    memset(&controller_addr, 0, sizeof(controller_addr));
    controller_addr.sin_family = AF_INET;
    controller_addr.sin_port = htons(local_switch_port);
    controller_addr.sin_addr.s_addr = inet_addr(local_ip.c_str());
    memset(&switch_addr, 0, sizeof(switch_addr));
    switch_addr.sin_family = AF_INET;
    switch_addr.sin_port = htons(switch_port);
    switch_addr.sin_addr.s_addr = inet_addr(switch_ip.c_str());

    int switch_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(switch_fd == -1) {
        perror("socket");
        return -1;
    }
    if(bind(switch_fd, (struct sockaddr *)&controller_addr, sizeof(controller_addr)) == -1) {
        perror("bind");
        return -1;
    }
    
    for(int i = 0; i < pkt_processor_core_ids.size(); ++i) {
        pkt_processors[i]->run(pkt_processor_core_ids[i]);
    }
    
    std::cout << "Pkt processor started" << std::endl;
    if(connect(switch_fd, (struct sockaddr *)&switch_addr, sizeof(switch_addr)) == -1) {
        perror("connect");
        return -1;
    }
    std::cout << "Connection established" << std::endl;
    epoll_event sock_ev;
    sock_ev.events = EPOLLIN;
    sock_ev.data.fd = switch_fd;
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, switch_fd, &sock_ev) == -1) {
        perror("epoll_ctl");
        return -1;
    }
    int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if(timer_fd == -1) {
        perror("timerfd_create");
        return -1;
    }
    itimerspec timer_spec;
    timer_spec.it_interval.tv_nsec = 100000;
    timer_spec.it_value.tv_nsec = 100000;
    timer_spec.it_interval.tv_sec = 0;
    timer_spec.it_value.tv_sec = 0;
    if(timerfd_settime(timer_fd, 0, &timer_spec, NULL) == -1) {
        perror("timerfd_settime");
        return -1;
    }
    epoll_event timer_ev;
    timer_ev.events = EPOLLIN;
    timer_ev.data.fd = timer_fd;
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &timer_ev) == -1) {
        perror("epoll_ctl");
        return -1;
    }
    itimerspec timer_spec_2;
    timer_spec_2.it_interval.tv_nsec = 0;
    timer_spec_2.it_value.tv_nsec = 0;
    timer_spec_2.it_interval.tv_sec = 1;
    timer_spec_2.it_value.tv_sec = 1;
    int timer_fd_2 = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if(timer_fd_2 == -1) {
        perror("timerfd_create");
        return -1;
    }
    if(timerfd_settime(timer_fd_2, 0, &timer_spec_2, NULL) == -1) {
        perror("timerfd_settime");
        return -1;
    }
    epoll_event timer_ev_2;
    timer_ev_2.events = EPOLLIN;
    timer_ev_2.data.fd = timer_fd_2;
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd_2, &timer_ev_2) == -1) {
        perror("epoll_ctl");
        return -1;
    }

    char send_buffer[ETH_FRAME_LEN], recv_buffer[ETH_FRAME_LEN];
    my_pair_t add_pairs[1024];
    my_key_t del_keys[1024];
    epoll_event events[2];
    while(true) {
        int nfds = epoll_wait(epoll_fd, events, 2, -1);
        if(nfds == -1) {
            perror("epoll_wait");
            return -1;
        }
        if(nfds > 0) {
            for(int i = 0; i < nfds; i++) {
                if(events[i].data.fd == switch_fd) {
                    ssize_t recv_size = recv(switch_fd, recv_buffer, ETH_FRAME_LEN, 0);
                    if (recv_size == -1) {
                        perror("recv");
                        return -1;
                    }
                    if(recv_size == 0) {
                        std::cerr << "Connection closed by switch" << std::endl;
                        return -1;
                    }
                    operation_type_t op = (operation_type_t)recv_buffer[0];
                    switch(op) {
                        case UPDATE_RULE: {
                            uint8_t add_size = recv_buffer[1];
                            uint8_t del_size = recv_buffer[2];
                            size_t now_bytes = 3;
                            for(int i = 0; i < add_size; ++i) {
                                char *key = recv_buffer + now_bytes;
                                now_bytes += strlen(key) + 1;
                                my_data_t *data = new my_data_t;
                                data->d_index = recv_buffer[now_bytes];
                                now_bytes += 1;
                                data->offload_flag = recv_buffer[now_bytes];
                                now_bytes += 1;
                                rule_controller->add_balancing_rule(key, data);
                            }
                            for(int i = 0; i < del_size; ++i) {
                                char *key = recv_buffer + now_bytes;
                                rule_controller->del_balancing_rule(key);
                                now_bytes += strlen(key) + 1;
                            }
                            break;
                        }
                        case UPDATE_V_INFO: {
                            rule_controller->update_virtual_server_info((server_info_t *)(recv_buffer + 1));
                            break;
                        }
                        case UPDATE_D_INDEX: {
                            uint8_t add_size = recv_buffer[1];
                            uint8_t del_size = recv_buffer[2];
                            size_t now_bytes = 3;
                            for(int i = 0; i < add_size; ++i) {
                                uint8_t index = recv_buffer[now_bytes];
                                now_bytes += 1;
                                server_info_t *server_info = new server_info_t;
                                memcpy(server_info, recv_buffer + now_bytes, sizeof(server_info_t));
                                rule_controller->add_d_index_rule(index, server_info);
                                now_bytes += sizeof(server_info_t);
                            }
                            for(int i = 0; i < del_size; ++i) {
                                uint8_t index = recv_buffer[now_bytes];
                                rule_controller->del_d_index_rule(index);
                                now_bytes += 1;
                            }
                            break;
                        }
                        default:
                            std::cerr << "Unknown operation type:" << (int)op << std::endl;
                            break;
                    }
                }
                else if(events[i].data.fd == timer_fd) {
                    
                    uint64_t exp;
                    ssize_t s = read(timer_fd, &exp, 8);
                    if(s == -1) {
                        perror("read");
                        return -1;
                    }
                    ssize_t send_size = entry_controller->get_offloaded_entries(send_buffer);
                    #ifdef DEBUG
                    if(send_size != 0)
                        std::cout << "Send size:" << send_size << std::endl;
                    #endif
                    if(send_size == -1) {
                        return -1;
                    }
                    if(send_size == 0) {
                        continue;
                    }
                    
                    if(send(switch_fd, send_buffer, send_size, 0) == -1) {
                        perror("send");
                        return -1;
                    }
                    
                }
                else if(events[i].data.fd == timer_fd_2) {
                    uint64_t exp;
                    ssize_t s = read(timer_fd_2, &exp, 8);
                    if(s == -1) {
                        perror("read");
                        return -1;
                    }
                    rte_eth_stats stats;
                    if(rte_eth_stats_get(pkt_processor_t::port_id, &stats) == -1) {
                        perror("rte_eth_stats_get");
                        return -1;
                    }
                    std::cout << "Received packets:" << stats.ipackets << std::endl;
                    std::cout << "Sent packets:" << stats.opackets << std::endl;
                    std::cout << "Received bytes:" << stats.ibytes << std::endl;
                    std::cout << "Sent bytes:" << stats.obytes << std::endl;
                    std::cout << "Received errors:" << stats.ierrors << std::endl;
                    std::cout << "Sent errors:" << stats.oerrors << std::endl;
                    std::cout << "Drop:" << stats.imissed << std::endl;
                    std::cout << "Received mbuf allocation errors:" << stats.rx_nombuf << std::endl;
                    // for(int i = 0; i < dpdk_config_args.queue_size; ++i) {
                    //     std::cout << "Queue " << i << " received packets:" << stats.q_ipackets[i] << std::endl;
                    //     std::cout << "Queue " << i << " sent packets:" << stats.q_opackets[i] << std::endl;
                    //     std::cout << "Queue " << i << " received bytes:" << stats.q_ibytes[i] << std::endl;
                    //     std::cout << "Queue " << i << " sent bytes:" << stats.q_obytes[i] << std::endl;
                    //     std::cout << "Queue " << i << " received errors:" << stats.q_errors[i] << std::endl;
                    // }
                }
                
            }
        }
    }
    return 0;
}