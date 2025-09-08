#ifndef MIRESGA_UTILS_H_
#define MIRESGA_UTILS_H_

#include "miresga_config.h" 
#include <infiniband/verbs.h>
#include <cstdint>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
extern "C" {
    #include <rte_ether.h>
    #include <rte_malloc.h>
}

struct RDMAInfo_t {
    ibv_gid  gid;
    uint32_t qpn;
    uint64_t addr;
    uint64_t rkey;
};

struct DPDKConfig_t {
    char *pci_addr;
    uint32_t rx_ring_size;
    uint32_t tx_ring_size;
    uint32_t num_mbufs;
    uint32_t mbuf_cache_size;
    uint32_t mbuf_data_room_size;
    uint32_t burst_size;
    uint32_t queue_size;
};

enum MiresgaStatus_t {
    OK = 0,
    INTERNAL_ERROR,
    INVALID_PARAMETER,
    BUSYING, 
    OUT_OF_RANGE,
    UNKNOWN
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

enum FlowState_t {
    INIT,
    BACKEND_SYN,
    OFFLOAD,
    ESTABLISHED,
};

struct ServerInfo_t
{
    rte_ether_addr mac;
    uint32_t       ip;
    uint16_t       port;
};

struct MiresgaOFTKey_t
{
    uint8_t  modify_flag;
    uint8_t  crc;
    uint32_t client_ip;
    uint16_t client_port;
};

extern uint64_t packed_key(const MiresgaOFTKey_t key);

struct MiresgaOFTData_t
{
    uint8_t flow_state;
    uint8_t d_index;
};

struct MiresgaOFTEntry_t
{
    MiresgaOFTKey_t  key;
    MiresgaOFTData_t data;
};

class MiresgaFlowData_t
{
public:
    void*             recv_pkt;
    size_t            recv_pkt_size;
    FlowState_t       state;
    MiresgaOFTEntry_t entry_data;
    MiresgaFlowData_t();
    ~MiresgaFlowData_t();
};

class RDMABuffer_t {
public:
    void*      buffer;
    ibv_mr*    mr;
    size_t     size;
    std::atomic<size_t> num_used;
    size_t num_sent;
    std::shared_mutex mutex;
    RDMABuffer_t(size_t size, ibv_pd* pd);
    ~RDMABuffer_t();
    size_t add_new_data(void* data, size_t data_size);
    void create_sge(ibv_sge& sge, bool& changed);
    void remove_last_send_data();
};

#endif