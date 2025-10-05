#ifndef RDMA_ENGINE_H_
#define RDMA_ENGINE_H_

#include "fmt/format.h"
#include "fmt/ranges.h"
#include "spdlog/spdlog.h"
#include "miresga_utils.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <vector>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unordered_map>

class RDMAEngine
{
private:
    uint8_t _id;
    ibv_send_wr* bad_send_wr;
    ibv_recv_wr* bad_recv_wr;
    RDMAInfo_t* _local_rdma_info;
    RDMAInfo_t* _remote_rdma_info;
    void* _send_buffer;
    void* _recv_buffer;
    size_t _send_buffer_size;
    size_t _recv_buffer_size;
    ibv_mr* _send_mr;
    ibv_mr* _recv_mr;
    ibv_qp* _qp;
    int _timer_fd;
    int _epoll_fd;
    itimerspec _timer_value;
    void _create_qp(ibv_pd* pd, ibv_cq* cq);
    void _change_qp_to_init();
    void _change_qp_to_rtr();
    void _change_qp_to_rts();
public:
    RDMAEngine(uint8_t id, ibv_pd* pd, ibv_cq* cq, ibv_gid& gid, int epoll_fd);   
    ~RDMAEngine();
    void init_engine(RDMAInfo_t* remote_rdma_info);
    void add_flow_data(std::vector<MiresgaOFTEntry_t>& data_vec);
    void sync_start();
    void sync_complete();
    RDMAInfo_t* get_local_rdma_info();
    void* get_recv_addr();
};

#endif