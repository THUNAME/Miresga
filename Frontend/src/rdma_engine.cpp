#include "rdma_engine.h"

auto logger = spdlog::stdout_color_mt("RDMAEngine");

__attribute__((always_inline)) 
void 
RDMAEngine::_create_qp(
    ibv_pd* pd, 
    ibv_cq* cq
) 
{
    SPDLOG_LOGGER_DEBUG(logger, "Creating Queue Pair for RDMA Engine ID: {}", _remote_id);
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
    if (unlikely(!_qp)) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to create Queue Pair for RDMA Engine ID: {}", _remote_id);
        throw std::runtime_error("Failed to create Queue Pair");
    }
    _local_rdma_info->qpn = _qp->qp_num;
    SPDLOG_LOGGER_DEBUG(logger, "Local QPN for RDMA Engine ID {}: 0x{:x}", _remote_id, _local_rdma_info->qpn);
}

__attribute__((always_inline)) 
void 
RDMAEngine::_change_qp_to_init() 
{
    SPDLOG_LOGGER_DEBUG(logger, "Changing Queue Pair state to INIT for RDMA Engine ID: {}", _remote_id);
    ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_state = IBV_QPS_INIT;
    qp_attr.port_num = 1;
    qp_attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;
    if (unlikely(ibv_modify_qp(_qp, &qp_attr, IBV_QP_STATE | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS | IBV_QP_PKEY_INDEX))) {
        throw std::runtime_error("Failed to modify Queue Pair");
    }
}

__attribute__((always_inline)) 
void 
RDMAEngine::_change_qp_to_rtr() 
{
    SPDLOG_LOGGER_DEBUG(logger, "Changing Queue Pair state to RTR for RDMA Engine ID: {}", _remote_id);
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
    if (unlikely(ibv_modify_qp(_qp, &qp_attr, IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MIN_RNR_TIMER | IBV_QP_MAX_DEST_RD_ATOMIC)))
    {
        throw std::runtime_error("Failed to modify Queue Pair to RTR");
    }
}

__attribute__((always_inline)) 
void 
RDMAEngine::_change_qp_to_rts() 
{
    SPDLOG_LOGGER_DEBUG(logger, "Changing Queue Pair state to RTS for RDMA Engine ID: {}", _remote_id);
    ibv_qp_attr qp_attr;
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_state = IBV_QPS_RTS;
    qp_attr.timeout = 14;
    qp_attr.retry_cnt = 7;
    qp_attr.rnr_retry = 7;
    qp_attr.sq_psn = 0;
    qp_attr.max_rd_atomic = 1;
    if (unlikely(ibv_modify_qp(_qp, &qp_attr, IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC)))
    {
        throw std::runtime_error("Failed to modify Queue Pair to RTS");
    }
}

__attribute__((always_inline)) 
RDMAEngine::RDMAEngine(
    uint8_t remote_id, 
    ibv_pd* pd, 
    ibv_cq* cq, 
    ibv_gid& gid,
    int epoll_fd
) {
    _remote_id = remote_id;
    _local_rdma_info = new RDMAInfo_t();
    _send_buffer = reinterpret_cast<void*>(new char[RDMA_BUFFER_SIZE]);
    _send_mr = ibv_reg_mr(pd, _send_buffer, RDMA_BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
    if (unlikely(!_send_mr)) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to register memory region for RDMA Engine ID: {}", _remote_id);
        throw std::runtime_error("Failed to register memory region");
    }
    _recv_buffer = reinterpret_cast<void*>(new char[RDMA_BUFFER_SIZE]);
    _recv_mr = ibv_reg_mr(pd, _recv_buffer, RDMA_BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
    if (unlikely(!_recv_mr)) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to register memory region for RDMA Engine ID: {}", _remote_id);
        throw std::runtime_error("Failed to register memory region");
    }
    _local_rdma_info->addr = reinterpret_cast<uint64_t>(_recv_mr->addr);
    _local_rdma_info->rkey = _recv_mr->rkey;
    memcpy(&_local_rdma_info->gid, &gid, sizeof(ibv_gid));
    SPDLOG_LOGGER_DEBUG(logger, "Local RDMA Info for Engine ID {}: RECV ADDR: 0x{:x}, RECV RKEY: 0x{:x}", _remote_id, _local_rdma_info->addr, _local_rdma_info->rkey);
    _create_qp(pd, cq);
    _change_qp_to_init();
    _timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (_timer_fd == -1) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to create timerfd for RDMA Engine ID: {}", _remote_id);
        throw std::runtime_error("Failed to create timerfd");
    }
    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.u32 = _remote_id | TIMER_MASK;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, _timer_fd, &ev) == -1) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to add timerfd to epoll for RDMA Engine ID: {}", _remote_id);
        throw std::runtime_error("Failed to add timerfd to epoll");
    }
    memset(&_timer_value, 0, sizeof(_timer_value));
    _timer_value.it_value.tv_nsec = 100000000; // 100ms
    // Do not set interval to make it a one-shot timer
    // Do not start the timer yet; it will be started in sync_complete
    _epoll_fd = epoll_fd;
}

__attribute__((always_inline)) 
RDMAEngine::~RDMAEngine()
{
    if (_qp) {
        ibv_destroy_qp(_qp);
    }
    if (_local_rdma_info) {
        delete _local_rdma_info;
    }
    if (_send_mr) {
        ibv_dereg_mr(_send_mr);
    }
    if (_recv_mr) {
        ibv_dereg_mr(_recv_mr);
    }
    epoll_ctl(_epoll_fd, EPOLL_CTL_DEL, _timer_fd, nullptr);
    close(_timer_fd);
    delete [] reinterpret_cast<char*>(_send_buffer);
    delete [] reinterpret_cast<char*>(_recv_buffer);
    delete _remote_rdma_info;
}

__attribute__((always_inline)) 
void 
RDMAEngine::init_engine(
    RDMAInfo_t* remote_rdma_info
) 
{
    if (unlikely(remote_rdma_info == nullptr)) {
        SPDLOG_LOGGER_ERROR(logger, "Remote RDMA info is null for Engine ID: {}", _remote_id);
        throw std::runtime_error("Remote RDMA info is null");
    }
    SPDLOG_LOGGER_DEBUG(logger, "Initializing RDMA Engine ID: {} with Remote QPN: 0x{:x}, Remote ADDR: 0x{:x}, Remote RKEY: 0x{:x}", 
                        _remote_id, remote_rdma_info->qpn, remote_rdma_info->addr, remote_rdma_info->rkey);
    _remote_rdma_info = remote_rdma_info;
    _change_qp_to_rtr();
    _change_qp_to_rts();
}

__attribute__((always_inline))
void 
RDMAEngine::add_flow_data(
    MiresgaFlowData_t* flow_data
) {
    SPDLOG_LOGGER_DEBUG(logger, "Adding flow data to RDMA Engine ID: {}", _remote_id);
    Operation_t operation;
    operation.type = INSERT;
    operation.entry = flow_data->entry_data;
    _operation_queue.add_operation(operation);
}

__attribute__((always_inline)) 
void 
RDMAEngine::add_flow_data(
    std::vector<MiresgaOFTEntry_t>& data_vec
) {
    _operation_queue.add_old_entries(data_vec);
}

__attribute__((always_inline))
void
RDMAEngine::del_flow_data(
    MiresgaFlowData_t* flow_data
) {
    Operation_t operation;
    operation.type = DELETE;
    operation.entry = flow_data->entry_data;
    _operation_queue.add_operation(operation);
}

__attribute__((always_inline)) 
void 
RDMAEngine::sync_start(
) {
    uint64_t exp;
    if (read(_timer_fd, &exp, sizeof(uint64_t)) != sizeof(uint64_t)) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to read timerfd for RDMA Engine ID: {}", _remote_id);
        throw std::runtime_error("Failed to read timerfd");
    }
    ibv_sge send_sge;
    uint32_t imm_data = static_cast<uint32_t>(_operation_queue.get_all_operations(_send_buffer));
    ssize_t send_len = imm_data * sizeof(Operation_t);
    if (imm_data > 0) {
        send_sge.addr = reinterpret_cast<uint64_t>(_send_mr->addr);
        send_sge.length = send_len;
        send_sge.lkey = _send_mr->lkey;
        SPDLOG_LOGGER_DEBUG(logger, "Sending {} bytes of flow data for RDMA Engine ID: {}", send_sge.length, _remote_id);
    } else {
        // No sge to send, reset the timer. Otherwise, the timer will never be restarted.
        timerfd_settime(_timer_fd, 0, &_timer_value, nullptr); // Restart the timer for the next sync
        return;
    }
    ibv_send_wr send_wr;
    memset(&send_wr, 0, sizeof(send_wr));
    send_wr.wr_id = _remote_id;
    send_wr.sg_list = &send_sge;
    send_wr.num_sge = 1;
    send_wr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
    send_wr.imm_data = imm_data;
    send_wr.wr.rdma.remote_addr = _remote_rdma_info->addr;
    send_wr.wr.rdma.rkey = _remote_rdma_info->rkey;
    send_wr.send_flags = IBV_SEND_SIGNALED;
    send_wr.next = nullptr;
    ibv_post_send(_qp, &send_wr, &bad_send_wr);
}

__attribute__((always_inline)) 
RDMAInfo_t* 
RDMAEngine::get_local_rdma_info() 
{
    return _local_rdma_info;
}

__attribute__((always_inline)) 
void* 
RDMAEngine::get_recv_addr() 
{
    return _recv_buffer;
}

__attribute__((always_inline)) 
void 
RDMAEngine::sync_complete() 
{
    if (timerfd_settime(_timer_fd, 0, &_timer_value, nullptr) == -1) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to set timerfd for RDMA Engine ID: {}", _remote_id);
        throw std::runtime_error("Failed to set timerfd");
    }
}

__attribute__((always_inline))
void
RDMAEngine::post_recv_wr() 
{
    #pragma unroll
    for (int i = 0; i < 5; ++i) {
        ibv_recv_wr recv_wr;
        memset(&recv_wr, 0, sizeof(recv_wr));
        recv_wr.wr_id = _remote_id; // Use remote_id to identify the engine in the completion
        recv_wr.sg_list = nullptr;
        recv_wr.num_sge = 0;
        recv_wr.next = nullptr;
        if (ibv_post_recv(_qp, &recv_wr, &bad_recv_wr)) {
            SPDLOG_LOGGER_ERROR(logger, "Failed to post receive WR for RDMA Engine ID: {}", _remote_id);
            throw std::runtime_error("Failed to post receive WR");
        }
    }
}