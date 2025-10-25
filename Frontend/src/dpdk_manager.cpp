#include "dpdk_manager.h"

static auto logger = spdlog::stdout_color_mt("DPDKManager");

DPDKManager::DPDKManager(int argc, char **argv, DPDKConfig_t* dpdk_config) {
    SPDLOG_LOGGER_DEBUG(logger, "Initializing DPDK EAL");
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to initialize DPDK EAL");
        throw std::runtime_error("Failed to initialize DPDK EAL");
    }

    SPDLOG_LOGGER_DEBUG(logger, "Creating mbuf pool");
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", dpdk_config->num_mbufs,
                                        dpdk_config->mbuf_cache_size, 0,
                                        dpdk_config->mbuf_data_room_size, 
                                        rte_socket_id());
    if (mbuf_pool == nullptr) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to create mbuf pool");
        throw std::runtime_error("Failed to create mbuf pool");
    }

    SPDLOG_LOGGER_DEBUG(logger, "Setting up Ethernet device");
    port_id = 0;
    if (rte_eth_dev_count_avail() == 0) {
        SPDLOG_LOGGER_ERROR(logger, "No available Ethernet devices");
        throw std::runtime_error("No available Ethernet devices");
    }

    ret = rte_eth_dev_get_port_by_name(dpdk_config->pci_addr, &port_id) != 0;
    if (ret < 0) {
        SPDLOG_LOGGER_ERROR(logger, "Ethernet device {} not found", dpdk_config->pci_addr);
        throw std::runtime_error(fmt::format("Ethernet device {} not found", dpdk_config->pci_addr));
    }

    rte_eth_conf port_conf = {};
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM;
    port_conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    port_conf.rx_adv_conf.rss_conf.rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP;
    SPDLOG_LOGGER_DEBUG(logger, "Configuring Ethernet device");
    ret = rte_eth_dev_configure(port_id, dpdk_config->queue_size, 
                                dpdk_config->queue_size, &port_conf);
    if (ret < 0) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to configure Ethernet device");
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
    SPDLOG_LOGGER_DEBUG(logger, "Setting up {} RX/TX queues", dpdk_config->queue_size);
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
    
    SPDLOG_LOGGER_DEBUG(logger, "Starting Ethernet device");
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
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
    rte_eal_cleanup();
}

void DPDKManager::init_dpdk_manager(int argc, char **argv, DPDKConfig_t* dpdk_config) {
    if (_instance == nullptr) {
        SPDLOG_LOGGER_DEBUG(logger, "Initializing DPDKManager singleton instance");
        _instance = new DPDKManager(argc, argv, dpdk_config);
    }
}

DPDKManager* DPDKManager::get_instance() {
    if (_instance == nullptr) {
        SPDLOG_LOGGER_ERROR(logger, "DPDKManager not initialized");
        throw std::runtime_error("DPDKManager not initialized");
    }
    return _instance;
}

void DPDKManager::destroy_instance() {
    if (_instance != nullptr) {
        SPDLOG_LOGGER_WARN(logger, "Destroying DPDKManager instance");
        uint32_t core_id;
        RTE_LCORE_FOREACH_WORKER(core_id) {
            rte_eal_wait_lcore(core_id);
            SPDLOG_LOGGER_DEBUG(logger, "Worker on core {} stopped", core_id);
        }
        delete _instance;
        _instance = nullptr;
    }
}