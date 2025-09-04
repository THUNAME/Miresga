#ifndef RDMA_ENGINE_H_
#define RDMA_ENGINE_H_

#include "miresga_utils.h"
#include <unordered_map>
#include <vector>

class RDMAEngine
{
private:
    uint8_t _id;
    ibv_send_wr* bad_send_wr;
    ibv_recv_wr* bad_recv_wr;
    RDMAInfo_t* _local_rdma_info;
    RDMAInfo_t* _remote_rdma_info;
    RDMABuffer_t* _send_add_buffer;
    RDMABuffer_t* _send_del_buffer;
    RDMABuffer_t* _recv_buffer;
    ibv_qp* _qp;
    void _create_qp(ibv_pd* pd, ibv_cq* cq);
    void _change_qp_to_init();
    void _change_qp_to_rtr();
    void _change_qp_to_rts();
public:
    RDMAEngine(uint8_t id, ibv_pd* pd, ibv_cq* cq, ibv_gid& gid);   
    ~RDMAEngine();
    void init_engine(RDMAInfo_t* remote_rdma_info);
    void add_flow_data(MiresgaOFTEntry_t* data);
    void del_flow_data(MiresgaOFTKey_t* data);
    void sync();
    RDMAInfo_t* get_local_rdma_info();
    void* get_recv_addr();
};

#endif