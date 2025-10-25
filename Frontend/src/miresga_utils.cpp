#include "miresga_utils.h"

static auto logger = spdlog::stdout_color_mt("MiresgaUtils");

__attribute__((always_inline)) MiresgaFlowData_t::MiresgaFlowData_t() {
    recv_pkt = nullptr;
    recv_pkt_size = 0;
    state = INIT;
}

__attribute__((always_inline)) MiresgaFlowData_t::~MiresgaFlowData_t() {
    if (recv_pkt) {
        delete [] static_cast<char*>(recv_pkt);
        recv_pkt = nullptr;
    }
}

__attribute__((always_inline)) uint64_t packed_key(const MiresgaOFTKey_t key) {
    return (static_cast<uint64_t>(key.crc) << 48) |
           (static_cast<uint64_t>(key.client_ip) << 16) |
           static_cast<uint64_t>(key.client_port);
}
