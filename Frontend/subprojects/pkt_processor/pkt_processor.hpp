#ifndef PKT_PROCESSOR_HPP_
#define PKT_PROCESSOR_HPP_

#include "concurrentqueue/concurrentqueue.h"
#include "my_config.hpp"
#include "flow_data.hpp"
#include "rule_controller.hpp"
#include "libcuckoo/cuckoohash_map.hh"
extern "C" {
    #include <rte_eal.h>
    #include <rte_ethdev.h>
    #include <rte_ether.h>
    #include <rte_tcp.h>
    #include <rte_ip.h>
    #include <rte_malloc.h>
    #include <rte_mempool.h>
}

const uint8_t option_char[] = {
    // MSS: type 2, length 4, value 1460 (0x05B4 in hex, big-endian)
    0x02, 0x04, 0x05, 0xB4,
    // NOP: type 1
    0x01,
    // NOP: type 1
    0x01,
    // SACK Permitted: type 4, length 2
    0x04, 0x02,
    // NOP: type 1
    0x01,
    // Window Scale: type 3, length 3, value 9
    0x03, 0x03, 0x09
};

struct dpdk_config_t {
    char *pci_addr;
    uint32_t rx_ring_size;
    uint32_t tx_ring_size;
    uint32_t num_mbufs;
    uint32_t mbuf_cache_size;
    uint32_t mbuf_data_room_size;
    uint32_t burst_size;
    uint32_t queue_size;
};



class pkt_processor_t {
private:
    static libcuckoo::cuckoohash_map<uint64_t, flow_data_t *> *flow_hash_map;
    static rte_mempool *mbuf_pool;
    static rule_controller_t *rule_controller;
    static dpdk_config_t *dpdk_config;
    static std::vector<uint8_t> crc8_table;
    static moodycamel::ConcurrentQueue<my_pair_t> *add_queue;
    static moodycamel::ConcurrentQueue<my_key_t> *del_queue;
    bool exit_flag;
    int queue_id;
    moodycamel::ProducerToken add_token;
    moodycamel::ProducerToken del_token;
    char *parse_payload(char *payload, int payload_size, int &size);
    status_t process_pkts(rte_mbuf **recv_pkts, size_t pkt_num);
    static inline uint8_t calculate_crc8(uint32_t ip, uint16_t port);
    static inline status_t forward_inbound_pkt(uint8_t d_index, rte_mbuf *recv_buf, rte_mbuf *send_buf);
    static inline status_t forward_outbound_pkt(rte_mbuf *recv_buf, rte_mbuf *send_buf);
    static inline status_t reply_rst_pkt(rte_mbuf *recv_buf, rte_mbuf *send_buf);
    static inline status_t send_rst_pkt(uint8_t d_index, rte_mbuf *recv_buf, rte_mbuf *send_buf);
    static inline status_t send_cached_pkt(uint8_t d_index, char * cached_pkt, rte_mbuf *send_buf, size_t size);
    static inline status_t send_syn_pkt(uint8_t d_index, rte_mbuf *recv_buf, rte_mbuf *send_buf);
    static int worker_run_warpper(void *args);
    int worker_fun(void *args);
public:
    static uint16_t port_id;
    pkt_processor_t() = delete;
    pkt_processor_t(const pkt_processor_t &pkt_processor) = delete;
    pkt_processor_t(int queue_id);
    ~pkt_processor_t() = default;
    void run(int core_id);
    void stop();
    static status_t init_static_variable(int argc, char **argv, dpdk_config_t* dpdk_config, 
                                         rule_controller_t *rule_controller, 
                                         moodycamel::ConcurrentQueue<my_pair_t> *add_queue,
                                         moodycamel::ConcurrentQueue<my_key_t> *del_queue,
                                         libcuckoo::cuckoohash_map<uint64_t, flow_data_t *> *flow_hash_map);
    static void destroy_static_variable();
    status_t status;
};


#endif