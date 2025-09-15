#ifndef CONTROLLER_H_
#define CONTROLLER_H_

#define TIMER_PRESENTOR 0x0b0b0b0b

#include "client.h"
#include "fmt/format.h"
#include "fmt/ranges.h"
#include "spdlog/spdlog.h"
#include "nlohmann/json.hpp"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <queue>
#include <vector>
#include <thread>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <iostream>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/timerfd.h>
#include <unordered_set>
#include <unordered_map>

#define MAX_EPOLL_EVENTS 16

enum ControllerState_t {
    INIT,
    NORMAL,
    WAIT_RDMA_INFO,
    WAIT_RDMA_INIT,
    WAIT_SYNC
};

enum OperationType_t {
    COMPLETE = 0,
    UPDATE_RULE,
    UPDATE_D_INDEX,
    UPDATE_V_INFO,
    OFFLOAD_ENTRIES,
    INIT_RDMA_ENGINE,
    SYNC_OLD_DATA,
    UPDATE_RDMA_INFO,
    RDMA_START,
    RDMA_STOP
};

struct RDMAInfo_t {
    uint8_t  gid[16];
    uint32_t qpn;
    uint64_t addr;
    uint64_t rkey;
};

struct RuleEntry_t {
    uint8_t offload_flag;
    uint8_t d_index;
};

struct ServerInfo_t
{
    uint8_t        mac[6];
    uint32_t       ip;    // in network byte order
    uint16_t       port;  // in network byte order
};

class FrontendController_t {
private:
    inline static FrontendController_t* _instance = nullptr;
    int _socket_fd;
    int _epoll_fd;
    bool _exit_flag;
    uint8_t _updating_id;
    std::thread _controller_thread;
    SwitchClient_t* _client;
    ControllerState_t _state;
    std::unordered_map<std::string, RuleEntry_t> _rule_table;
    std::unordered_map<std::string, EgressPortEntry_t> _ip_2_egress_port; 
    std::unordered_map<uint8_t, EgressPortEntry_t> _id_2_egress_port;
    std::unordered_map<uint8_t, int> _id_2_socket_fd;
    std::unordered_map<int, uint8_t> _socket_fd_2_id;
    std::unordered_map<uint8_t, std::unordered_map<uint8_t, RDMAInfo_t>> _id_2_rdma_info;
    std::unordered_map<uint8_t, size_t> _id_2_num_crcs;
    std::unordered_map<uint8_t, std::vector<uint8_t>> _id_2_need_changed_crcs;
    std::unordered_map<uint8_t, std::unordered_map<uint8_t, std::vector<uint8_t>>> _id_2_sync_crcs;
    std::unordered_map<uint8_t, ServerInfo_t> _d_index_2_backend_server_info;
    std::vector<uint8_t> _active_ids;
    std::queue<uint8_t> _idle_ids;
    std::unordered_set<uint8_t> _wait_init_ids;
    std::unordered_set<uint8_t> _wait_rdma_info_ids;
    ServerInfo_t _virtual_server_info;
    FrontendController_t(std::string config_path);
    ~FrontendController_t();
    std::string _serializing_rule_table();
    std::string _serializing_d_index_table();
    std::string _serializing_v_info();
    void _main_loop();
    void _add_frontend(uint8_t id);
    void _remove_frontend(uint8_t id);
    void _update_rdma_info();
public:
    static void init_frontend_controller(std::string config_path);
    static FrontendController_t* get_instance();
    void start();
    void stop();
};

#endif