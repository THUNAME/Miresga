#ifndef RDMA_MANAGER_H_
#define RDMA_MANAGER_H_

#include "miresga_config.h"
#include "miresga_utils.h"
#include "rdma_engine.h"
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <stdexcept>
#include <sys/epoll.h>
#include <string>
#include <vector>

class RDMAManager
{
private:
    inline static RDMAManager* _instance = nullptr;
    uint8_t _local_id;
    std::unordered_map<uint8_t, std::pair<RDMAEngine*, bool>> _id_2_engines;
    std::unordered_map<uint8_t, uint8_t> _crc_2_id;
    ibv_context* _ctx;
    ibv_pd* _pd;
    ibv_gid _local_gid;
    ibv_comp_channel* _comp_channel;
    ibv_cq* _cq;
    RDMAManager(const char* dev_name, int epoll_fd);
    ~RDMAManager();
public:
    static void init_rdma_manager(const char* dev_name, int epoll_fd);
    static RDMAManager* get_instance();
    static void destroy_instance();
    std::string add_engine(uint8_t id);
    void update_engine(uint8_t id, RDMAInfo_t* remote_rdma_info, std::vector<uint8_t> crcs);
    void remove_engine(uint8_t id, std::unordered_map<uint8_t, uint8_t>& crc_2_id);
    void start_engine(uint8_t id);
    void sync_states();
    std::vector<ibv_wc> process_cqe();
    void add_flow_data(MiresgaOFTEntry_t* add_data);
    void add_old_flow_data(uint8_t remote_id, std::vector<MiresgaOFTEntry_t>& add_data_vec);
    void del_flow_data(MiresgaOFTKey_t* del_data);
    void* get_recv_addr(uint8_t id);
};

#endif