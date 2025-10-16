#include "flow_table.h"
#include "dpdk_manager.h"
#include "rdma_manager.h"
#include "rule_manager.h"
#include "pkt_processor.h"
#include "entry_manager.h"
#include "miresga_utils.h"
#include "miresga_config.h"
#include "nlohmann/json.hpp"
#include "controller_client.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <numa.h>

using json = nlohmann::json;

int main(int argc, char** argv) {
    // Just set SPDLOG_ACTIVE_LEVEL is not enough to set the log level. Although 
    // the SPDLOG_LOGGER_DEBUG macro will be compiled out, the logger level is still
    // set to info by default. So we need to set the log level explicitly.
    #if DEBUG == 1
    spdlog::set_level(spdlog::level::debug);
    #else
    spdlog::set_level(spdlog::level::info);
    #endif
    std::ifstream dpdk_config_fs("../config/dpdk_config.json");
    json dpdk_config_json;
    dpdk_config_fs >> dpdk_config_json;
    DPDKConfig_t dpdk_config;
    std::string pci_addr_str = dpdk_config_json["pci_addr"].get<std::string>();
    dpdk_config.pci_addr = pci_addr_str.data();
    dpdk_config.rx_ring_size = static_cast<uint32_t>(dpdk_config_json["rx_ring_size"]);
    dpdk_config.tx_ring_size = static_cast<uint32_t>(dpdk_config_json["tx_ring_size"]);
    dpdk_config.num_mbufs = static_cast<uint32_t>(dpdk_config_json["num_mbufs"]);
    dpdk_config.mbuf_cache_size = static_cast<uint32_t>(dpdk_config_json["mbuf_cache_size"]);
    dpdk_config.mbuf_data_room_size = static_cast<uint32_t>(dpdk_config_json["mbuf_data_room_size"]);
    dpdk_config.burst_size = static_cast<uint32_t>(dpdk_config_json["burst_size"]);
    std::vector<int> pkt_processor_core_ids;
    auto res = dpdk_config_json["pkt_processor_core_ids"];
    if (res.is_array()) {
        for (auto core_id : res) {
            pkt_processor_core_ids.push_back(core_id.get<int>());
        }
    } else if(!res.is_null()) {
        pkt_processor_core_ids.push_back(res.get<int>());
    } else {
        throw std::runtime_error("Invalid pkt_processor_core_ids in dpdk_config.json");
    }
    dpdk_config_fs.close();
    dpdk_config.queue_size = pkt_processor_core_ids.size();
    DPDKManager::init_dpdk_manager(argc, argv, &dpdk_config);

    std::ifstream controller_config_fs("../config/controller_config.json");
    json controller_config_json;
    controller_config_fs >> controller_config_json;
    std::string switch_ip_str = controller_config_json["switch_ip"];
    uint16_t switch_port = static_cast<uint32_t>(controller_config_json["switch_port"]);
    int socket_id = 0;
    if (controller_config_json.contains("numa_node")) {
        std::string numa_node_str = controller_config_json["numa_node"];
        socket_id = std::stoi(numa_node_str);
        if (numa_available() == -1) {
            throw std::runtime_error("NUMA is not available");
        }
        numa_set_bind_policy(1);
        numa_bind(numa_parse_nodestring(numa_node_str.c_str()));
         
    }
    controller_config_fs.close();

    std::ifstream rdma_config_fs("../config/rdma_config.json");
    json rdma_config_json;
    rdma_config_fs >> rdma_config_json;
    std::string rdma_dev_name = rdma_config_json["dev_name"];
    rdma_config_fs.close();
    ControllerClient::init_controller_client(switch_ip_str.data(), switch_port, 
                                             rdma_dev_name.data());
    ControllerClient* controller_client = ControllerClient::get_instance();
    std::vector<PktProcessor*> pkt_processors;
    for (size_t i = 0; i < pkt_processor_core_ids.size(); ++i) {
        PktProcessor* processor = new PktProcessor(i, socket_id);
        pkt_processors.push_back(processor);
        processor->start(pkt_processor_core_ids[i]);
    }
    std::string input_str;
    #ifndef DISPLAY_FLAG
    std::thread monitor_thread([&dpdk_config]() {
        uint64_t prev_ipackets = 0;
        uint64_t prev_opackets = 0;
        uint64_t prev_ibytes = 0;
        uint64_t prev_obytes = 0;
        uint64_t prev_ierrors = 0;
        uint64_t prev_oerrors = 0;
        uint64_t prev_q_ipackets[16] = {0};
        uint64_t prev_q_opackets[16] = {0};
        uint64_t prev_q_errors[16] = {0};
        std::ofstream log_file("/home/sxy/dpdk_throughput.csv");
        uint64_t prev_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        log_file << prev_timestamp << "," << prev_ibytes << "," << prev_obytes << std::endl;
        log_file.flush();

        while (true) {
            FlowTable* flow_table = FlowTable::get_instance();
            rte_eth_stats stats;
            int ret = rte_eth_stats_get(DPDKManager::get_instance()->port_id, &stats);
            SPDLOG_INFO("ipackets: {}", stats.ipackets - prev_ipackets);
            SPDLOG_INFO("opackets: {}", stats.opackets - prev_opackets);
            SPDLOG_INFO("ierrors: {}", stats.ierrors - prev_ierrors);
            SPDLOG_INFO("oerrors: {}", stats.oerrors - prev_oerrors);
            prev_ipackets = stats.ipackets;
            prev_opackets = stats.opackets;
            prev_ierrors = stats.ierrors;
            prev_oerrors = stats.oerrors;
            for (int i = 0; i < dpdk_config.queue_size; ++i) {
                SPDLOG_INFO("Queue {}: ipackets: {}, opackets: {}", i, stats.q_ipackets[i] - prev_q_ipackets[i], stats.q_opackets[i] - prev_q_opackets[i]);
                SPDLOG_INFO("Queue {}: errors: {}", i, stats.q_errors[i] - prev_q_errors[i]);
                prev_q_ipackets[i] = stats.q_ipackets[i];
                prev_q_opackets[i] = stats.q_opackets[i];
                prev_q_errors[i] = stats.q_errors[i];
            }
            uint64_t curr_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            uint64_t interval = curr_timestamp - prev_timestamp;
            if (interval == 0) {
                continue;
            }
            prev_timestamp = curr_timestamp;
            uint64_t ibytes = stats.ibytes;
            uint64_t obytes = stats.obytes;
            uint64_t bps_in = (ibytes - prev_ibytes) * 8 * 1000 / interval;
            uint64_t bps_out = (obytes - prev_obytes) * 8 * 1000 / interval;
            prev_ibytes = ibytes;
            prev_obytes = obytes;
            log_file << curr_timestamp << "," << bps_in << "," << bps_out << std::endl;
            log_file.flush();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });
    #endif
    while (true) {
        std::cin >> input_str;
        if (input_str == "exit") {
            for (auto processor : pkt_processors) {
                processor->stop();
                delete processor;
            }
            controller_client->stop();
            ControllerClient::destroy_instance();
            DPDKManager::destroy_instance();
            EntryManager::destroy_instance();
            FlowTable::destroy_instance();
            RuleManager::destroy_instance();
            RDMAManager::destroy_instance();
            break;
        }
    }
    return 0;
}