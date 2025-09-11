#ifndef PKT_PROCESSOR_H_
#define PKT_PROCESSOR_H_

#include "fmt/format.h"
#include "fmt/ranges.h"
#include "flow_table.h"
#include "dpdk_manager.h"
#include "rule_manager.h"
#include "rdma_manager.h"
#include "spdlog/spdlog.h"
#include "entry_manager.h"
#include "concurrentqueue.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <thread>
#include <string>

class PktProcessor {
private:
    bool _exit_flag;
    int _queue_id;
    int _socket_id;
    std::thread _processor_thread;
    moodycamel::ProducerToken& _add_token;
    moodycamel::ProducerToken& _del_token;
    DPDKManager* _dpdk_manager;
    RuleManager* _rule_manager;
    RDMAManager* _rdma_manager;
    EntryManager* _entry_manager;
    FlowTable* _flow_table;
    void _main_loop();
    void _process_pkts(rte_mbuf** bufs, uint16_t nb_pkts);
    static int _worker_fun_wrapper(void* arg);
    static std::string _parse_payload(std::string payload);
    static uint8_t _calc_crc8(uint32_t ip, uint16_t port);
    MiresgaStatus_t _send_pkts(rte_mbuf** mbuf, size_t nb_pkts);
    void _get_inbound_normal_pkt(rte_mbuf* recv_mbuf, uint8_t d_index, rte_mbuf* send_mbuf);
    void _get_outbound_normal_pkt(rte_mbuf* recv_mbuf, rte_mbuf* send_mbuf);
    void _get_inbound_syn_pkt(rte_mbuf* recv_mbuf, uint8_t d_index, rte_mbuf* send_mbuf);
    void _get_inbound_rst_pkt(rte_mbuf* recv_mbuf, uint8_t d_index, rte_mbuf* send_mbuf);
    void _get_outbound_rst_pkt(rte_mbuf* recv_mbuf, rte_mbuf* send_mbuf);
    void _get_cached_pkt(char* cached_pkt, uint16_t cached_pkt_len, 
                         uint8_t d_index, rte_mbuf* send_mbuf);
public:
    PktProcessor(int queue_id, int socket_id = 0);
    ~PktProcessor();
    void start(int core_id);
    void stop();
};

#endif