#include "miresga_utils.h"

static auto logger = spdlog::stdout_color_mt("MiresgaUtils");

MiresgaFlowData_t::MiresgaFlowData_t() {
    recv_pkt = nullptr;
    recv_pkt_size = 0;
    state = INIT;
}

MiresgaFlowData_t::~MiresgaFlowData_t() {
    if (recv_pkt) {
        delete [] static_cast<char*>(recv_pkt);
        recv_pkt = nullptr;
    }
}

uint64_t packed_key(const MiresgaOFTKey_t key) {
    return (static_cast<uint64_t>(key.crc) << 48) |
           (static_cast<uint64_t>(key.client_ip) << 16) |
           static_cast<uint64_t>(key.client_port);
}

RDMABuffer_t::RDMABuffer_t(size_t size, ibv_pd* pd) {
    this->size = size;
    this->num_used = 0;
    this->num_sent = 0;
    buffer = static_cast<void*>(new char[size]);
    if (buffer == nullptr) {
        throw std::runtime_error("Failed to allocate RDMA buffer");
    }
    mr = ibv_reg_mr(pd, buffer, size, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
    if (mr == nullptr) {
        delete[] static_cast<char*>(buffer);
        throw std::runtime_error("Failed to register MR");
    }
}

RDMABuffer_t::~RDMABuffer_t() {
    if (mr) {
        ibv_dereg_mr(mr);
        mr = nullptr;
    }
    if (buffer) {
        delete[] static_cast<char*>(buffer);
        buffer = nullptr;
    }
}

size_t RDMABuffer_t::add_new_data(void* data, size_t data_size) {
    size_t add_size = 0;
    size_t offset = 0;
    {
        std::shared_lock<std::shared_mutex> lock(mutex);
        size_t expected = num_used.load(std::memory_order_acquire);
        do{
            offset = expected;
            if (expected + data_size > size) {
                add_size = size - expected;
                if (add_size == 0) {
                    return 0;
                }
            }
            else {
                add_size = data_size;
            }
        } while (!num_used.compare_exchange_weak(
            expected, 
            expected + add_size, 
            std::memory_order_acq_rel, 
            std::memory_order_acquire
        ));
    }
    SPDLOG_LOGGER_DEBUG(logger, "Added {} bytes to RDMA buffer, total used: {}", add_size, num_used.load());
    SPDLOG_LOGGER_DEBUG(logger, "Should add size: {}", data_size);
    memcpy(reinterpret_cast<void*>(reinterpret_cast<char*>(buffer) + offset), data, add_size);
    return add_size;
}

void RDMABuffer_t::create_sge(ibv_sge& sge, bool& changed) {
    size_t need_send = 0;
    {
        std::shared_lock<std::shared_mutex> lock(mutex);
        need_send = num_used.load() - num_sent;
    }
    if (need_send == 0) {
        // SPDLOG_LOGGER_DEBUG(logger, "No new data to send");
        changed = false;
    }
    else{
        sge.addr = reinterpret_cast<uint64_t>(buffer) + num_sent;
        sge.length = need_send;
        sge.lkey = mr->lkey;
        num_sent = num_used;
        changed = true;
        SPDLOG_LOGGER_DEBUG(logger, "Prepared SGE with {} bytes to send", need_send);
    }
}

void RDMABuffer_t::remove_last_send_data() {
    SPDLOG_LOGGER_DEBUG(logger, "Removing last sent data of {} bytes from RDMA buffer", num_sent);
    std::unique_lock<std::shared_mutex> lock(mutex);
    memcpy(buffer, reinterpret_cast<void*>(reinterpret_cast<char*>(buffer) + num_sent), size - num_sent);
    num_used -= num_sent;
    num_sent = 0;
}
