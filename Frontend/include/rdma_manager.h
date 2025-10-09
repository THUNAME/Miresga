#ifndef RDMA_MANAGER_H_
#define RDMA_MANAGER_H_

#include "fmt/format.h"
#include "fmt/ranges.h"
#include "flow_table.h"
#include "rdma_engine.h"
#include "spdlog/spdlog.h"
#include "miresga_utils.h"
#include "miresga_config.h"

#include <string>
#include <vector>
#include <stdexcept>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <unordered_set>
#include <unordered_map>

class RDMAManager
{
private:
    inline static RDMAManager* _instance = nullptr;
    uint8_t _local_id;
    std::unordered_map<uint8_t, RDMAEngine*> _id_2_engines;
    std::unordered_map<uint8_t, std::vector<uint8_t>> _id_2_crcs;
    std::unordered_map<uint8_t, uint8_t> _crc_2_id;
    ibv_context* _ctx;
    ibv_pd* _pd;
    ibv_gid _local_gid;
    ibv_comp_channel* _comp_channel;
    ibv_cq* _cq;
    int _epoll_fd;
    volatile bool _updating_flag;
    FlowTable* _flow_table;
    RDMAManager(const char* dev_name, int epoll_fd);
    ~RDMAManager();
public:
    static void init_rdma_manager(const char* dev_name, int epoll_fd);
    static RDMAManager* get_instance();
    static void destroy_instance();
    std::string add_engine(uint8_t id);
    void update_engine(uint8_t id, RDMAInfo_t* remote_rdma_info);
    void update_crcs(std::unordered_map<uint8_t, std::vector<uint8_t>>& id_2_crcs);
    void remove_engine(uint8_t id, std::unordered_map<uint8_t, std::vector<uint8_t>>& _id_2_crcs);
    void start_engine(uint8_t id);
    void sync_states(uint8_t id);
    void sync_complete(uint8_t id);
    void add_old_flow_data(uint8_t id, std::vector<MiresgaOFTEntry_t>& data_vec);
    void add_flow_data(MiresgaFlowData_t* flow_data);
    void del_flow_data(MiresgaFlowData_t* flow_data);
    std::vector<ibv_wc> process_cqe();
    void* get_recv_addr(uint8_t id);
};

#endif