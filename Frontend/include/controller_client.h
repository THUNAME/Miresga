#ifndef CONTROLLER_CLIENT_H_
#define CONTROLLER_CLIENT_H_

#include "fmt/format.h"
#include "fmt/ranges.h"
#include "flow_table.h"
#include "rdma_manager.h"
#include "rule_manager.h"
#include "miresga_utils.h"
#include "entry_manager.h"
#include "spdlog/spdlog.h"
#include "concurrentqueue.h"
#include "controller_connector.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <thread>
#include <shared_mutex>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <linux/if_ether.h>

class ControllerClient
{
private:
    inline static ControllerClient* _instance = nullptr;
    FlowTable* _flow_table;
    ControllerConnector* _connector;
    EntryManager* _entry_manager;
    RuleManager* _rule_manager;
    RDMAManager* _rdma_manager;
    std::thread _client_thread;
    bool _exit_flag;
    char _recv_buffer[ETH_FRAME_LEN];
    char _send_buffer[ETH_FRAME_LEN];
    int _epoll_fd;
    int _offload_timerfd;
    int _sync_timerfd;
    bool _update_info();
    void _main_loop();
    ControllerClient() = delete;
    ControllerClient(ControllerClient const&) = delete;
    ControllerClient& operator=(ControllerClient const&) = delete;
    ControllerClient(char* switch_ip, uint16_t switch_port, 
                     char* rdma_dev_name);
    ~ControllerClient();
public:
    static void init_controller_client(char* switch_ip, uint16_t switch_port, 
                                       char* rdma_dev_name);
    static ControllerClient* get_instance();
    static void destroy_instance();
    void stop();
};

#endif