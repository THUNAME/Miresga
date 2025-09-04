#include "rdma_engine.h"

void RDMAEngine::_create_qp(ibv_pd* pd, ibv_cq* cq) 
{
    ibv_qp_init_attr qp_init_attr;
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    qp_init_attr.send_cq = cq;
    qp_init_attr.recv_cq = cq;
    qp_init_attr.qp_type = IBV_QPT_RC;
    qp_init_attr.cap = {
        .max_send_wr = 10,
        .max_recv_wr = 10,
        .max_send_sge = 2,
        .max_recv_sge = 2};
    qp_init_attr.sq_sig_all = 1;
    _qp = ibv_create_qp(pd, &qp_init_attr);
    if (!_qp) {
        throw std::runtime_error("Failed to create Queue Pair");
    }
}

void RDMAEngine::_change_qp_to_init() 
{
    ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_state = IBV_QPS_INIT;
    qp_attr.port_num = 1;
    qp_attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;
    if (ibv_modify_qp(_qp, &qp_attr, IBV_QP_STATE | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS | IBV_QP_PKEY_INDEX)) {
        throw std::runtime_error("Failed to modify Queue Pair");
    }
    _local_rdma_info->qpn = _qp->qp_num;
}

void RDMAEngine::_change_qp_to_rtr() 
{
    ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_state = IBV_QPS_RTR;
    qp_attr.path_mtu = IBV_MTU_4096;
    qp_attr.dest_qp_num = _remote_rdma_info->qpn;
    qp_attr.max_dest_rd_atomic = 1;
    qp_attr.rq_psn = 0;
    qp_attr.min_rnr_timer = 12;
    qp_attr.ah_attr.is_global = 1;
    memcpy(&qp_attr.ah_attr.grh.dgid, &_remote_rdma_info->gid, sizeof(ibv_gid));
    qp_attr.ah_attr.grh.sgid_index = 3;
    qp_attr.ah_attr.grh.hop_limit = 64;
    qp_attr.ah_attr.port_num = 1;
    if (ibv_modify_qp(_qp, &qp_attr, IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MIN_RNR_TIMER | IBV_QP_MAX_DEST_RD_ATOMIC))
    {
        throw std::runtime_error("Failed to modify Queue Pair to RTR");
    }
}

void RDMAEngine::_change_qp_to_rts() 
{
    ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_state = IBV_QPS_RTS;
    qp_attr.timeout = 14;
    qp_attr.retry_cnt = 7;
    qp_attr.rnr_retry = 7;
    qp_attr.sq_psn = 0;
    qp_attr.max_rd_atomic = 1;
    if (ibv_modify_qp(_qp, &qp_attr, IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC))
    {
        throw std::runtime_error("Failed to modify Queue Pair to RTS");
    }
}

RDMAEngine::RDMAEngine(uint8_t id, ibv_pd* pd, ibv_cq* cq, ibv_gid& gid)
{
    _id = id;
    _local_rdma_info = new RDMAInfo_t();
    _send_add_buffer = new RDMABuffer_t(RDMA_SEND_ADD_BUFFER_SIZE, pd);
    _send_del_buffer = new RDMABuffer_t(RDMA_SEND_DEL_BUFFER_SIZE, pd);
    _recv_buffer = new RDMABuffer_t(RDMA_RECV_BUFFER_SIZE, pd);
    _local_rdma_info->addr = reinterpret_cast<uint64_t>(_recv_buffer->mr->addr);
    _local_rdma_info->rkey = _recv_buffer->mr->rkey;
    _create_qp(pd, cq);
    _change_qp_to_init();
}

RDMAEngine::~RDMAEngine()
{
    if (_qp) {
        ibv_destroy_qp(_qp);
    }
    if (_local_rdma_info) {
        delete _local_rdma_info;
    }
    delete _send_add_buffer;
    delete _send_del_buffer;
    delete _recv_buffer;
    delete _remote_rdma_info;
}

void RDMAEngine::init_engine(RDMAInfo_t* remote_rdma_info) {
    if (!remote_rdma_info) {
        throw std::runtime_error("Remote RDMA info is null");
    }
    _remote_rdma_info = remote_rdma_info;
    _change_qp_to_rtr();
    _change_qp_to_rts();
    ibv_recv_wr recv_wr;
    memset(&recv_wr, 0, sizeof(recv_wr));
    recv_wr.wr_id = _id;
    recv_wr.next = nullptr;
    recv_wr.num_sge = 0;
    recv_wr.sg_list = nullptr;
    ibv_post_recv(_qp, &recv_wr, &bad_recv_wr);
}

void RDMAEngine::add_flow_data(MiresgaOFTEntry_t* data) {
    _send_add_buffer->add_new_data(static_cast<void*>(data), sizeof(MiresgaOFTEntry_t));
}

void RDMAEngine::del_flow_data(MiresgaOFTKey_t* data) {
    _send_del_buffer->add_new_data(static_cast<void*>(data), sizeof(MiresgaOFTKey_t));
}

void RDMAEngine::sync() {
    ibv_sge all_sge[2];
    int num_sge = 0;
    bool changed = false;
    bool changed_1 = false, changed_2 = false;
    _send_add_buffer->create_sge(all_sge[0], changed_1);
    _send_del_buffer->create_sge(all_sge[1], changed_2);
    ibv_send_wr send_wr;
    memset(&send_wr, 0, sizeof(send_wr));
    send_wr.wr_id = _id;
    if (changed_1 == true) {
        send_wr.sg_list = all_sge;
    }
    else if (changed_2 == true) {
        send_wr.sg_list = &all_sge[1];
    }
    else {
        return;
    }
    if (changed_1 == true && changed_2 == true) {
        send_wr.num_sge = 2;
    }
    else {
        send_wr.num_sge = 1;
    }
    uint32_t imm_data = 0;
    if (changed_1) {
        imm_data |= (all_sge[0].length / sizeof(MiresgaOFTEntry_t)) << 16;
    }
    if (changed_2) {
        imm_data |= all_sge[1].length / sizeof(MiresgaOFTKey_t);
    }
    send_wr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
    send_wr.imm_data = imm_data;
    send_wr.wr.rdma.remote_addr = _remote_rdma_info->addr;
    send_wr.wr.rdma.rkey = _remote_rdma_info->rkey;
    send_wr.send_flags = IBV_SEND_SIGNALED;
    send_wr.next = nullptr;
    ibv_post_send(_qp, &send_wr, &bad_send_wr);
    ibv_recv_wr recv_wr;
    memset(&recv_wr, 0, sizeof(recv_wr));
    recv_wr.wr_id = _id;
    recv_wr.next = nullptr;
    recv_wr.num_sge = 0;
    recv_wr.sg_list = nullptr;
    ibv_post_recv(_qp, &recv_wr, &bad_recv_wr);
}

RDMAInfo_t* RDMAEngine::get_local_rdma_info() {
    return _local_rdma_info;
}

void* RDMAEngine::get_recv_addr() {
    return _recv_buffer->buffer;
}