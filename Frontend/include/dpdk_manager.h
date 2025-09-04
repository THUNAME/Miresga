#ifndef DPDK_MANAGER_H_
#define DPDK_MANAGER_H_

#include "miresga_utils.h"
extern "C" {
    #include <rte_eal.h>
    #include <rte_ethdev.h>
    #include <rte_ether.h>
    #include <rte_tcp.h>
    #include <rte_ip.h>
    #include <rte_malloc.h>
    #include <rte_mempool.h>
}

class DPDKManager {
private:
    inline static DPDKManager* _instance = nullptr;
    DPDKManager() = delete;
    DPDKManager(DPDKManager const&) = delete;
    DPDKManager& operator=(DPDKManager const&) = delete;
    DPDKManager(int argc, char **argv, DPDKConfig_t* dpdk_config);
    ~DPDKManager();
public:
    DPDKConfig_t* dpdk_config;
    rte_mempool* mbuf_pool;
    rte_ether_addr source_mac;
    uint16_t port_id;
    static void init_dpdk_manager(int argc, char **argv, DPDKConfig_t* dpdk_config);
    static DPDKManager* get_instance();
    static void destroy_instance();
    
};

#endif