#include "dpdk_manager.h"

DPDKManager::DPDKManager(int argc, char **argv, DPDKConfig_t* dpdk_config) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        throw std::runtime_error("Failed to initialize DPDK EAL");
    }

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", dpdk_config->num_mbufs,
                                        dpdk_config->mbuf_cache_size, 0,
                                        dpdk_config->mbuf_data_room_size, rte_socket_id());
    if (mbuf_pool == nullptr) {
        throw std::runtime_error("Failed to create mbuf pool");
    }

    port_id = 0;
    if (rte_eth_dev_count_avail() == 0) {
        throw std::runtime_error("No available Ethernet devices");
    }

    rte_eth_conf port_conf = {};
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM;
    port_conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    port_conf.rx_adv_conf.rss_conf.rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP;

    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret < 0) {
        throw std::runtime_error("Failed to configure Ethernet device");
    }

    rte_eth_dev_info dev_info;
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret < 0)
    {
        throw std::runtime_error("Failed to get device info");
    }
    rte_eth_rxconf rxconf = dev_info.default_rxconf;
    rte_eth_txconf txconf = dev_info.default_txconf;

    txconf.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    txconf.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
    for (int i = 0; i < dpdk_config->queue_size; ++i) {
        ret = rte_eth_rx_queue_setup(port_id, i, dpdk_config->rx_ring_size,
                                     rte_eth_dev_socket_id(port_id), &rxconf, mbuf_pool);
        if (ret < 0) {
            throw std::runtime_error("Failed to setup RX queue");
        }
        ret = rte_eth_tx_queue_setup(port_id, i, dpdk_config->tx_ring_size,
                                     rte_eth_dev_socket_id(port_id), &txconf);
        if (ret < 0) {
            throw std::runtime_error("Failed to setup TX queue");
        }
    }

    ret = rte_eth_promiscuous_enable(port_id);
    if (ret < 0)
    {
        throw std::runtime_error("Failed to enable promiscuous mode");  
    }
    
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        throw std::runtime_error("Failed to start Ethernet device");
    }

    ret = rte_eth_macaddr_get(port_id, &source_mac);
    if (ret < 0) {
        throw std::runtime_error("Failed to get MAC address");
    }
    this->dpdk_config = dpdk_config;
}

DPDKManager::~DPDKManager() {
    rte_mempool_free(mbuf_pool);
    for (int i = 0; i < dpdk_config->queue_size; ++i) {
        rte_eth_dev_rx_queue_stop(port_id, i);
        rte_eth_dev_tx_queue_stop(port_id, i);
    }
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
    rte_eal_cleanup();
}

void DPDKManager::init_dpdk_manager(int argc, char **argv, DPDKConfig_t* dpdk_config) {
    if (_instance == nullptr) {
        _instance = new DPDKManager(argc, argv, dpdk_config);
    }
}

DPDKManager* DPDKManager::get_instance() {
    if (_instance == nullptr) {
        throw std::runtime_error("DPDKManager not initialized");
    }
    return _instance;
}

void DPDKManager::destroy_instance() {
    if (_instance != nullptr) {
        delete _instance;
        _instance = nullptr;
    }
}