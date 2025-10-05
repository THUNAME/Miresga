#include "pkt_processor.h"

static auto logger = spdlog::stdout_color_mt("PktProcessor");

static const uint8_t option_char[] = {
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

PktProcessor::PktProcessor(
    int queue_id, 
    int socket_id
) : _exit_flag(false), 
    _queue_id(queue_id), 
    _socket_id(socket_id),
    _dpdk_manager(DPDKManager::get_instance()),
    _rule_manager(RuleManager::get_instance()),
    _entry_manager(EntryManager::get_instance()),
    _flow_table(FlowTable::get_instance()) {
    SPDLOG_LOGGER_INFO(logger, "PktProcessor created on queue {} and socket {}", queue_id, socket_id);
    _crc8_table.resize(256);
    for (int i = 0; i < 256; i++) {
        uint8_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x80) {
                crc = (crc << 1) ^ 0x07; // 使用多项式0x07
            } else {
                crc = crc << 1;
            }
        }
        _crc8_table[i] = crc;
    }
    _add_token = _entry_manager->get_add_queue_token();
    _del_token = _entry_manager->get_del_queue_token();
}

PktProcessor::~PktProcessor() {
    stop();
}

__attribute__((always_inline)) 
uint8_t 
PktProcessor::_calc_crc8(
    uint32_t ip, 
    uint16_t port
) {
    uint8_t crc = 0;
    uint8_t data[6];
    data[0] = (ip >> 0) & 0xff;
    data[1] = (ip >> 8) & 0xff;
    data[2] = (ip >> 16) & 0xff;
    data[3] = (ip >> 24) & 0xff;
    data[4] = (port >> 0) & 0xff;
    data[5] = (port >> 8) & 0xff;
    SPDLOG_LOGGER_DEBUG(logger, "{:x}", fmt::join(data, data + 6, ", "));
    // 计算CRC8
    crc = _crc8_table[crc ^ data[0]];
    crc = _crc8_table[crc ^ data[1]];
    crc = _crc8_table[crc ^ data[2]];
    crc = _crc8_table[crc ^ data[3]];
    crc = _crc8_table[crc ^ data[4]];
    crc = _crc8_table[crc ^ data[5]];
    return crc;
}

__attribute__((always_inline)) 
std::string 
PktProcessor::_parse_payload(
    std::string payload
) {
    // We provide a simple parsing function here. Users can modify it to fit their own payload format.
    // We assume we use the url path in HTTP GET request as the payload.
    size_t pos1 = payload.find("/");
    if (pos1 == std::string::npos) return "";
    pos1++;
    size_t pos2 = payload.find(" ", pos1);
    if (pos2 == std::string::npos) return "";
    std::string parsed_payload =  payload.substr(pos1, pos2 - pos1);
    SPDLOG_LOGGER_DEBUG(logger, "Parsed payload: {}", parsed_payload);
    return parsed_payload;
}

__attribute__((always_inline)) 
MiresgaStatus_t 
PktProcessor::_send_pkts(
    rte_mbuf** mbuf, 
    size_t nb_pkts
) {
    uint16_t nb_tx = rte_eth_tx_burst(_dpdk_manager->port_id, _queue_id, mbuf, nb_pkts);
    MiresgaStatus_t status = MiresgaStatus_t::OK;
    if (unlikely(nb_tx != nb_pkts)) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to send all packets, sent {}/{}", nb_tx, nb_pkts);
        status = MiresgaStatus_t::INTERNAL_ERROR;
        rte_pktmbuf_free_bulk(mbuf + nb_tx, nb_pkts - nb_tx);
    }
    SPDLOG_LOGGER_DEBUG(logger, "Sent {} packets", nb_tx);
    return status;
}

__attribute__((always_inline)) 
void 
PktProcessor::_get_inbound_normal_pkt(
    rte_mbuf* recv_mbuf, 
    uint8_t d_index, 
    rte_mbuf* send_mbuf) 
{
    void* recv_pkt_data = rte_pktmbuf_mtod(recv_mbuf, void*);
    rte_ether_hdr* send_eth_hdr = rte_pktmbuf_mtod(send_mbuf, rte_ether_hdr*);
    rte_ipv4_hdr* send_ip_hdr = (rte_ipv4_hdr*)(send_eth_hdr + 1);
    rte_tcp_hdr* send_tcp_hdr = (rte_tcp_hdr*)(send_ip_hdr + 1);
    memcpy(send_eth_hdr, recv_pkt_data, recv_mbuf->data_len);
    ServerInfo_t* server_info = nullptr;
    if(unlikely(_rule_manager->get_backend_server_info(d_index, &server_info) != MiresgaStatus_t::OK)) {
        return;
    }
    rte_ether_addr_copy(&_dpdk_manager->source_mac, &send_eth_hdr->src_addr);
    rte_ether_addr_copy(&server_info->mac, &send_eth_hdr->dst_addr);
    send_ip_hdr->dst_addr = server_info->ip;
    send_ip_hdr->hdr_checksum = 0;
    send_tcp_hdr->dst_port = server_info->port;
    send_tcp_hdr->cksum = 0;
    send_mbuf->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM;
    send_mbuf->l2_len = sizeof(rte_ether_hdr);
    send_mbuf->l3_len = 20;
    send_mbuf->l4_len = (send_tcp_hdr->data_off >> 4) * 4;
    send_mbuf->data_len = ntohs(send_ip_hdr->total_length) + sizeof(rte_ether_hdr);
    send_mbuf->pkt_len = send_mbuf->data_len;
}

__attribute__((always_inline)) 
void 
PktProcessor::_get_outbound_normal_pkt(
    rte_mbuf* recv_mbuf, 
    rte_mbuf* send_mbuf
) {
    void* recv_pkt_data = rte_pktmbuf_mtod(recv_mbuf, void*);
    rte_ether_hdr* send_eth_hdr = rte_pktmbuf_mtod(send_mbuf, rte_ether_hdr*);
    rte_ipv4_hdr* send_ip_hdr = (rte_ipv4_hdr*)(send_eth_hdr + 1);
    rte_tcp_hdr* send_tcp_hdr = (rte_tcp_hdr*)(send_ip_hdr + 1);
    memcpy(send_eth_hdr, recv_pkt_data, recv_mbuf->data_len);
    ServerInfo_t* virtual_server_info = nullptr;
    if(unlikely(_rule_manager->get_virtual_server_info(&virtual_server_info) != MiresgaStatus_t::OK)) {
        return;
    }
    rte_ether_addr_copy(&_dpdk_manager->source_mac, &send_eth_hdr->src_addr);
    rte_ether_addr_copy(&virtual_server_info->mac, &send_eth_hdr->dst_addr);
    send_ip_hdr->src_addr = virtual_server_info->ip;
    send_ip_hdr->hdr_checksum = 0;
    send_tcp_hdr->src_port = virtual_server_info->port;
    send_tcp_hdr->cksum = 0;
    send_mbuf->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM;
    send_mbuf->l2_len = sizeof(rte_ether_hdr);
    send_mbuf->l3_len = 20;
    send_mbuf->l4_len = (send_tcp_hdr->data_off >> 4) * 4;
    send_mbuf->data_len = ntohs(send_ip_hdr->total_length) + sizeof(rte_ether_hdr);
    send_mbuf->pkt_len = send_mbuf->data_len;
}

__attribute__((always_inline)) 
void 
PktProcessor::_get_inbound_syn_pkt(
    rte_mbuf* recv_mbuf, 
    uint8_t d_index, 
    rte_mbuf* send_mbuf
) {
    void* recv_pkt_data = rte_pktmbuf_mtod(recv_mbuf, void*);
    rte_ether_hdr* send_eth_hdr = rte_pktmbuf_mtod(send_mbuf, rte_ether_hdr*);
    rte_ipv4_hdr* send_ip_hdr = (rte_ipv4_hdr*)(send_eth_hdr + 1);
    rte_tcp_hdr* send_tcp_hdr = (rte_tcp_hdr*)(send_ip_hdr + 1);
    memcpy(send_eth_hdr, recv_pkt_data, sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_tcp_hdr) + sizeof(option_char));
    ServerInfo_t* server_info = nullptr;
    if(unlikely(_rule_manager->get_backend_server_info(d_index, &server_info) != MiresgaStatus_t::OK)) {
        return;
    }
    rte_ether_addr_copy(&_dpdk_manager->source_mac, &send_eth_hdr->src_addr);
    rte_ether_addr_copy(&server_info->mac, &send_eth_hdr->dst_addr);
    send_ip_hdr->dst_addr = server_info->ip;
    send_ip_hdr->version_ihl = (sizeof(rte_ipv4_hdr) / 4) + (send_ip_hdr->version_ihl & 0xf0);
    send_ip_hdr->total_length = htons(sizeof(rte_ipv4_hdr) + sizeof(rte_tcp_hdr) + sizeof(option_char));
    send_ip_hdr->hdr_checksum = 0;
    send_tcp_hdr->dst_port = server_info->port;
    send_tcp_hdr->tcp_flags = RTE_TCP_SYN_FLAG;
    send_tcp_hdr->data_off = ((sizeof(rte_tcp_hdr) + sizeof(option_char)) / 4) << 4;
    send_tcp_hdr->sent_seq = htonl(ntohl(send_tcp_hdr->sent_seq) - 1);
    send_tcp_hdr->recv_ack = htonl(ntohl(send_tcp_hdr->recv_ack) - 1);
    send_tcp_hdr->cksum = 0;
    memcpy((char*)(send_tcp_hdr + 1), option_char, sizeof(option_char));
    send_mbuf->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM;
    send_mbuf->l2_len = sizeof(rte_ether_hdr);
    send_mbuf->l3_len = sizeof(rte_ipv4_hdr);
    send_mbuf->l4_len = sizeof(rte_tcp_hdr) + sizeof(option_char);
    send_mbuf->data_len = ntohs(send_ip_hdr->total_length) + sizeof(rte_ether_hdr);
    send_mbuf->pkt_len = send_mbuf->data_len;
}

__attribute__((always_inline)) 
void 
PktProcessor::_get_inbound_rst_pkt(
    rte_mbuf* recv_mbuf, 
    uint8_t d_index, 
    rte_mbuf* send_mbuf
) {
    void* recv_pkt_data = rte_pktmbuf_mtod(recv_mbuf, void*);
    rte_ether_hdr* send_eth_hdr = rte_pktmbuf_mtod(send_mbuf, rte_ether_hdr*);
    rte_ipv4_hdr* send_ip_hdr = (rte_ipv4_hdr*)(send_eth_hdr + 1);
    rte_tcp_hdr* send_tcp_hdr = (rte_tcp_hdr*)(send_ip_hdr + 1);
    memcpy(send_eth_hdr, recv_pkt_data, sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_tcp_hdr));
    ServerInfo_t* server_info = nullptr;
    if(unlikely(_rule_manager->get_backend_server_info(d_index, &server_info) != MiresgaStatus_t::OK)) {
        return;
    }
    rte_ether_addr_copy(&_dpdk_manager->source_mac, &send_eth_hdr->src_addr);
    rte_ether_addr_copy(&server_info->mac, &send_eth_hdr->dst_addr);
    send_ip_hdr->dst_addr = server_info->ip;
    send_ip_hdr->version_ihl = (sizeof(rte_ipv4_hdr) / 4) + (send_ip_hdr->version_ihl & 0xf0);
    send_ip_hdr->total_length = htons(sizeof(rte_ipv4_hdr) + sizeof(rte_tcp_hdr));
    send_ip_hdr->hdr_checksum = 0;
    send_tcp_hdr->dst_port = server_info->port;
    send_tcp_hdr->tcp_flags = RTE_TCP_RST_FLAG | RTE_TCP_ACK_FLAG;
    send_tcp_hdr->data_off = (sizeof(rte_tcp_hdr) / 4) << 4;
    send_tcp_hdr->cksum = 0;
    send_mbuf->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM;
    send_mbuf->l2_len = sizeof(rte_ether_hdr);
    send_mbuf->l3_len = sizeof(rte_ipv4_hdr);
    send_mbuf->l4_len = sizeof(rte_tcp_hdr);
    send_mbuf->data_len = sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_tcp_hdr);
    send_mbuf->pkt_len = send_mbuf->data_len;
}

__attribute__((always_inline)) 
void 
PktProcessor::_get_outbound_rst_pkt(
    rte_mbuf* recv_mbuf, 
    rte_mbuf* send_mbuf
) {
    void* recv_pkt_data = rte_pktmbuf_mtod(recv_mbuf, void*);
    rte_ether_hdr* send_eth_hdr = rte_pktmbuf_mtod(send_mbuf, rte_ether_hdr*);
    rte_ipv4_hdr* send_ip_hdr = (rte_ipv4_hdr*)(send_eth_hdr + 1);
    rte_tcp_hdr* send_tcp_hdr = (rte_tcp_hdr*)(send_ip_hdr + 1);
    memcpy(send_eth_hdr, recv_pkt_data, sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_tcp_hdr));
    ServerInfo_t* virtual_server_info = nullptr;
    if(unlikely(_rule_manager->get_virtual_server_info(&virtual_server_info) != MiresgaStatus_t::OK)) {
        return;
    }
    rte_ether_addr_copy(&_dpdk_manager->source_mac, &send_eth_hdr->src_addr);
    rte_ether_addr_copy(&virtual_server_info->mac, &send_eth_hdr->dst_addr);
    uint32_t tmp_ip = send_ip_hdr->src_addr;
    send_ip_hdr->src_addr = send_ip_hdr->dst_addr;
    send_ip_hdr->dst_addr = tmp_ip;
    send_ip_hdr->version_ihl = (sizeof(rte_ipv4_hdr) / 4) + (send_ip_hdr->version_ihl & 0xf0);
    send_ip_hdr->total_length = htons(sizeof(rte_ipv4_hdr) + sizeof(rte_tcp_hdr));
    send_ip_hdr->hdr_checksum = 0;
    uint16_t tmp_port = send_tcp_hdr->src_port;
    send_tcp_hdr->src_port = send_tcp_hdr->dst_port;
    send_tcp_hdr->dst_port = tmp_port;
    send_tcp_hdr->tcp_flags = RTE_TCP_RST_FLAG | RTE_TCP_ACK_FLAG;
    send_tcp_hdr->data_off = (sizeof(rte_tcp_hdr) / 4) << 4;
    uint32_t raw_seq_num = send_tcp_hdr->sent_seq;
    uint32_t raw_ack_num = send_tcp_hdr->recv_ack;
    send_tcp_hdr->sent_seq = raw_ack_num;
    send_tcp_hdr->recv_ack = htonl(ntohl(raw_seq_num) + 1);
    send_tcp_hdr->cksum = 0;
    send_mbuf->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM;
    send_mbuf->l2_len = sizeof(rte_ether_hdr);
    send_mbuf->l3_len = sizeof(rte_ipv4_hdr);
    send_mbuf->l4_len = sizeof(rte_tcp_hdr);
    send_mbuf->data_len = sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_tcp_hdr);
    send_mbuf->pkt_len = send_mbuf->data_len;
}

__attribute__((always_inline)) 
void PktProcessor::_get_cached_pkt(
    char* cached_pkt, 
    uint16_t cached_pkt_len, 
    uint8_t d_index, 
    rte_mbuf* send_mbuf
) {
    rte_ether_hdr* send_eth_hdr = rte_pktmbuf_mtod(send_mbuf, rte_ether_hdr*);
    rte_ipv4_hdr* send_ip_hdr = (rte_ipv4_hdr*)(send_eth_hdr + 1);
    rte_tcp_hdr* send_tcp_hdr = (rte_tcp_hdr*)(send_ip_hdr + 1);
    memcpy(send_eth_hdr, cached_pkt, cached_pkt_len);
    ServerInfo_t* server_info = nullptr;
    if(unlikely(_rule_manager->get_backend_server_info(d_index, &server_info) != MiresgaStatus_t::OK)) {
        return;
    }
    rte_ether_addr_copy(&_dpdk_manager->source_mac, &send_eth_hdr->src_addr);
    rte_ether_addr_copy(&server_info->mac, &send_eth_hdr->dst_addr);
    send_ip_hdr->dst_addr = server_info->ip;
    send_ip_hdr->hdr_checksum = 0;
    send_tcp_hdr->dst_port = server_info->port;
    send_tcp_hdr->cksum = 0;
    send_mbuf->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM;
    send_mbuf->l2_len = sizeof(rte_ether_hdr);
    send_mbuf->l3_len = 20;
    send_mbuf->l4_len = (send_tcp_hdr->data_off >> 4) * 4;
    send_mbuf->data_len = ntohs(send_ip_hdr->total_length) + sizeof(rte_ether_hdr);
    send_mbuf->pkt_len = send_mbuf->data_len;
}

void 
PktProcessor::_process_pkts(
    rte_mbuf** recv_mbufs, 
    uint16_t nb_pkts
) {
    rte_mbuf* send_mbufs[(nb_pkts << 1)];
    std::vector<std::pair<MiresgaOFTKey_t, MiresgaFlowData_t*>> add_data_vec;
    std::vector<MiresgaOFTKey_t> del_data_vec;
    size_t num_send_pkts = 0;
    if (unlikely(rte_pktmbuf_alloc_bulk(_dpdk_manager->mbuf_pool, send_mbufs, (nb_pkts << 1)) != 0)) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to allocate send mbufs");
        return;
    }
    for (int i = 0; i < nb_pkts; ++i) {
        uint16_t header_size = 0;
        uint32_t payload_len = 0;
        rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(recv_mbufs[i], rte_ether_hdr*);
        if (unlikely(eth_hdr->ether_type != htons(RTE_ETHER_TYPE_IPV4))) {
            SPDLOG_LOGGER_DEBUG(logger, "Not an IPv4 packet, ether_type: 0x{:x}", ntohs(eth_hdr->ether_type));
            continue;
        }
        rte_ipv4_hdr* ip_hdr = (rte_ipv4_hdr*)(eth_hdr + 1);
        header_size += (ip_hdr->version_ihl & 0x0f) << 2;
        if (unlikely(ip_hdr->next_proto_id != IPPROTO_TCP)) {
            SPDLOG_LOGGER_DEBUG(logger, "Not a TCP packet, next_proto_id: {}", ip_hdr->next_proto_id);
            continue;
        }
        rte_tcp_hdr* tcp_hdr = (rte_tcp_hdr*)((char*)ip_hdr + header_size);
        header_size += (tcp_hdr->data_off >> 4) * 4;
        payload_len = ntohs(ip_hdr->total_length) - header_size;
        uint8_t src_crc = _calc_crc8(ip_hdr->src_addr, tcp_hdr->src_port);
        uint8_t dst_crc = _calc_crc8(ip_hdr->dst_addr, tcp_hdr->dst_port);
        MiresgaOFTKey_t src_oft_key = {0, src_crc, ntohl(ip_hdr->src_addr), ntohs(tcp_hdr->src_port)};
        MiresgaOFTKey_t dst_oft_key = {0, dst_crc, ntohl(ip_hdr->dst_addr), ntohs(tcp_hdr->dst_port)};
        #ifdef DEBUG
        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];
        SPDLOG_LOGGER_DEBUG(logger, "Processing packet: src_ip={}, src_port={}, dst_ip={}, dst_port={}, flags=0x{:x}, payload_len={}",
                            inet_ntop(AF_INET, &ip_hdr->src_addr, src_ip_str, INET_ADDRSTRLEN),
                            ntohs(tcp_hdr->src_port),
                            inet_ntop(AF_INET, &ip_hdr->dst_addr, dst_ip_str, INET_ADDRSTRLEN),
                            ntohs(tcp_hdr->dst_port),
                            tcp_hdr->tcp_flags,
                            payload_len);
        #endif
        MiresgaFlowData_t* flow_data = _flow_table->get_flow(src_oft_key);
        if (flow_data != nullptr) {
            // Process inbound.
            SPDLOG_LOGGER_DEBUG(logger, "Found inbound flow");
            if (unlikely(tcp_hdr->tcp_flags & RTE_TCP_RST_FLAG)) {
                // Handle connection termination.
                SPDLOG_LOGGER_DEBUG(logger, "Inbound RST packet. Flow state: {}", static_cast<int>(flow_data->state));
                if (flow_data->state == FlowState_t::OFFLOAD) {
                    // Remove the entry from the offload table.
                    SPDLOG_LOGGER_DEBUG(logger, "Removing entry from offload table");
                    _entry_manager->del_entry(*_del_token, flow_data->entry_data.key);
                }
                if (flow_data->state >= FlowState_t::BACKEND_SYN) {
                    // Release the backend server.
                    SPDLOG_LOGGER_DEBUG(logger, "Releasing the connection with backend server");
                    _get_inbound_rst_pkt(recv_mbufs[i], flow_data->entry_data.data.d_index, send_mbufs[num_send_pkts]);
                    num_send_pkts++;
                }
                _flow_table->remove_flow(flow_data->entry_data.key);
                // No need to reply to the RST packet.
                continue;
            }
            if(unlikely(tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG)) {
                // Just replay with RST packet for simplicity.
                SPDLOG_LOGGER_DEBUG(logger, "Inbound FIN packet, replying with RST. Flow state: {}", static_cast<int>(flow_data->state));
                _get_outbound_rst_pkt(recv_mbufs[i], send_mbufs[num_send_pkts]);
                num_send_pkts++;
                if (flow_data->state == FlowState_t::OFFLOAD) {
                    // Remove the entry from the offload table.
                    SPDLOG_LOGGER_DEBUG(logger, "Removing entry from offload table");
                    _entry_manager->del_entry(*_del_token, flow_data->entry_data.key);
                }
                if (flow_data->state >= FlowState_t::BACKEND_SYN) {
                    // Release the backend server.
                    SPDLOG_LOGGER_DEBUG(logger, "Releasing the connection with backend server");
                    _get_inbound_rst_pkt(recv_mbufs[i], flow_data->entry_data.data.d_index, send_mbufs[num_send_pkts]);
                    num_send_pkts++;
                }
                _flow_table->remove_flow(flow_data->entry_data.key);
                continue;
            }
            SPDLOG_LOGGER_DEBUG(logger, "Inbound normal packet. Flow state: {}", static_cast<int>(flow_data->state));
            switch(flow_data->state) {
                case FlowState_t::ESTABLISHED:
                case FlowState_t::OFFLOAD: {
                    if (payload_len > 0) {
                        // Recieve new payload, parse it and check if we need to change the backend server.
                        SPDLOG_LOGGER_DEBUG(logger, "New request received");
                        std::string payload((char*)tcp_hdr + (tcp_hdr->data_off >> 4) * 4, 
                                            payload_len);
                        // Note: Here is an simple example. Users may implement more complex payload parsing logic here.
                        std::string parsed_payload = _parse_payload(payload);
                        RuleEntry_t* rule = nullptr;
                        if (unlikely(_rule_manager->get_rule(parsed_payload, &rule) != MiresgaStatus_t::OK)) {
                            SPDLOG_LOGGER_DEBUG(logger, "No matching rule for the new flow, ignore it.");
                            break;
                        }
                        // Backend server changed. Send RST to the old backend server and SYN to the new backend server.
                        if (rule->d_index != flow_data->entry_data.data.d_index) {
                            SPDLOG_LOGGER_DEBUG(logger, "Backend server changed from {} to {}, sending RST to the old backend and SYN to the new backend",
                                                static_cast<int>(flow_data->entry_data.data.d_index),
                                                static_cast<int>(rule->d_index));
                            _get_inbound_rst_pkt(recv_mbufs[i], flow_data->entry_data.data.d_index, send_mbufs[num_send_pkts]);
                            num_send_pkts++;
                            if (flow_data->state == FlowState_t::OFFLOAD) {
                                // Remove the entry from the offload table.
                                SPDLOG_LOGGER_DEBUG(logger, "Removing old entry from offload table");
                                _entry_manager->del_entry(*_del_token, flow_data->entry_data.key);
                            }
                            // Send SYN to the new backend server.
                            _get_inbound_syn_pkt(recv_mbufs[i], rule->d_index, send_mbufs[num_send_pkts]);
                            num_send_pkts++;
                            flow_data->entry_data.data.d_index = rule->d_index;
                            flow_data->entry_data.data.flow_state = rule->offload_flag == 1 ? static_cast<uint8_t>(FlowState_t::OFFLOAD) : static_cast<uint8_t>(FlowState_t::ESTABLISHED);
                            flow_data->state = FlowState_t::BACKEND_SYN;
                            if (flow_data->recv_pkt != nullptr) {
                                delete[] static_cast<char*>(flow_data->recv_pkt);
                            }
                            // Cache the received packet for later use.
                            flow_data->recv_pkt = new char[recv_mbufs[i]->data_len];
                            flow_data->recv_pkt_size = recv_mbufs[i]->data_len;
                            memcpy(flow_data->recv_pkt, rte_pktmbuf_mtod(recv_mbufs[i], char*), recv_mbufs[i]->data_len);
                        }
                        // Backend server not changed. Just forward the packet.
                        else {
                            SPDLOG_LOGGER_DEBUG(logger, "Backend server not changed, just forward the packet");
                            _get_inbound_normal_pkt(recv_mbufs[i], flow_data->entry_data.data.d_index, send_mbufs[num_send_pkts]);
                            num_send_pkts++;
                            if (flow_data->state == FlowState_t::OFFLOAD && rule->offload_flag == 0) {
                                flow_data->entry_data.data.flow_state = static_cast<uint8_t>(FlowState_t::ESTABLISHED);
                                _entry_manager->del_entry(*_del_token, flow_data->entry_data.key);
                                flow_data->state = FlowState_t::ESTABLISHED;
                            }
                            else if (flow_data->state == FlowState_t::ESTABLISHED && rule->offload_flag == 1) {
                                flow_data->entry_data.data.flow_state = static_cast<uint8_t>(FlowState_t::OFFLOAD);
                                _entry_manager->add_entry(*_add_token, flow_data->entry_data);
                                flow_data->state = FlowState_t::OFFLOAD;
                            }
                        }
                        // Do not update RDMA info. Add when the connection is established.
                    }
                    else {
                        SPDLOG_LOGGER_DEBUG(logger, "Not new request, just forward the packet");
                        _get_inbound_normal_pkt(recv_mbufs[i], flow_data->entry_data.data.d_index, send_mbufs[num_send_pkts]);
                        num_send_pkts++;
                    }
                    break;
                }
                case FlowState_t::BACKEND_SYN: {
                    if (likely(flow_data->recv_pkt != nullptr)) {
                        rte_ether_hdr *recv_ether_hdr = (rte_ether_hdr *)flow_data->recv_pkt;
                        rte_ipv4_hdr *recv_ip_hdr = (rte_ipv4_hdr *)(recv_ether_hdr + 1);
                        rte_tcp_hdr *recv_tcp_hdr = (rte_tcp_hdr *)(recv_ip_hdr + 1);
                        if (recv_tcp_hdr->sent_seq == tcp_hdr->sent_seq)
                        {  
                            SPDLOG_LOGGER_DEBUG(logger, "Received a retransmitted packet, resend the SYN packet to backend server");
                            _get_inbound_syn_pkt(recv_mbufs[i], flow_data->entry_data.data.d_index, send_mbufs[num_send_pkts]);
                            num_send_pkts++;
                        } else {
                            SPDLOG_LOGGER_DEBUG(logger, "Sequence number not match, may be a out-of-order packet. Ignore it.");
                        }
                    } else {
                        SPDLOG_LOGGER_DEBUG(logger, "No cached packet found, may be a bug.");
                    }
                    break;
                }
                default:
                    break;
            }
            continue;
        }
        flow_data = _flow_table->get_flow(dst_oft_key);
        if (flow_data != nullptr) {
            SPDLOG_LOGGER_DEBUG(logger, "Found outbound flow");
            // Process outbound.
            if (unlikely(tcp_hdr->tcp_flags & RTE_TCP_RST_FLAG)) {
                SPDLOG_LOGGER_DEBUG(logger, "Outbound RST packet. Flow state: {}", static_cast<int>(flow_data->state));
                // Handle connection termination.
                if (flow_data->state == FlowState_t::OFFLOAD) {
                    // Remove the entry from the offload table.
                    SPDLOG_LOGGER_DEBUG(logger, "Removing entry from offload table");
                    _entry_manager->del_entry(*_del_token, flow_data->entry_data.key);
                }   
                // Send RST to the client.
                SPDLOG_LOGGER_DEBUG(logger, "Sending RST to the client");
                _get_outbound_normal_pkt(recv_mbufs[i], send_mbufs[num_send_pkts]);
                num_send_pkts++;
                _flow_table->remove_flow(flow_data->entry_data.key);
                // No need to reply to the RST packet.
                continue;
            }
            if(unlikely(tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG)) {
                if(payload_len == 0) { 
                    SPDLOG_LOGGER_DEBUG(logger, "Outbound FIN packet, replying with RST. Flow state: {}", static_cast<int>(flow_data->state));
                    // Send RST to the client.
                    _get_outbound_rst_pkt(recv_mbufs[i], send_mbufs[num_send_pkts]);
                    num_send_pkts++;
                    // Send RST to the backend server.
                    _get_inbound_rst_pkt(recv_mbufs[i], flow_data->entry_data.data.d_index, send_mbufs[num_send_pkts]);
                    num_send_pkts++;
                    if (flow_data->state == FlowState_t::OFFLOAD) {
                        SPDLOG_LOGGER_DEBUG(logger, "Removing entry from offload table");
                        // Remove the entry from the offload table.
                        _entry_manager->del_entry(*_del_token, flow_data->entry_data.key);
                    }
                    _flow_table->remove_flow(flow_data->entry_data.key);
                } else {
                    SPDLOG_LOGGER_DEBUG(logger, "Outbound FIN packet with payload, sending to client. Flow state: {}", static_cast<int>(flow_data->state));
                    // Just forward the packet.
                    _get_outbound_normal_pkt(recv_mbufs[i], send_mbufs[num_send_pkts]);
                    num_send_pkts++;
                }
                continue;
            }
            switch(flow_data->state) {
                case FlowState_t::BACKEND_SYN:
                {
                    if (unlikely((tcp_hdr->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG)) == 0)) {
                        // Ignore non-SYN-ACK packets in BACKEND_SYN state.
                        SPDLOG_LOGGER_DEBUG(logger, "Not a SYN-ACK packet, ignore it.");
                        break;
                    }
                    if (flow_data->entry_data.data.flow_state == static_cast<uint8_t>(FlowState_t::OFFLOAD)) {
                        SPDLOG_LOGGER_DEBUG(logger, "Adding entry to offload table");
                        _entry_manager->add_entry(*_add_token, flow_data->entry_data);
                        flow_data->state = FlowState_t::OFFLOAD;
                    }
                    else {
                        flow_data->state = FlowState_t::ESTABLISHED;
                    }
                    // Send the cached packet to the backend server.
                    _get_cached_pkt(static_cast<char*>(flow_data->recv_pkt), flow_data->recv_pkt_size, flow_data->entry_data.data.d_index, send_mbufs[num_send_pkts]);
                    ++num_send_pkts;
                    break;
                }
                case FlowState_t::OFFLOAD:
                case FlowState_t::ESTABLISHED:
                {
                    SPDLOG_LOGGER_DEBUG(logger, "Outbound normal packet. Flow state: {}", static_cast<int>(flow_data->state));
                    // Just forward the packet.
                    _get_outbound_normal_pkt(recv_mbufs[i], send_mbufs[num_send_pkts]);
                    num_send_pkts++;
                    break;
                }
                default:
                    break;
            }
            continue;
        }
        // Process new flow.
        if (payload_len == 0) {
            SPDLOG_LOGGER_DEBUG(logger, "No payload in the new flow, ignore it.");
            continue;
        }
        std::string payload((char*)tcp_hdr + (tcp_hdr->data_off >> 4) * 4, 
                            payload_len);
        // Note: Here is an simple example. Users may implement more complex payload parsing logic here.
        std::string parsed_payload = _parse_payload(payload);
        RuleEntry_t* rule = nullptr;
        if (unlikely(_rule_manager->get_rule(parsed_payload, &rule) != MiresgaStatus_t::OK)) {
            SPDLOG_LOGGER_DEBUG(logger, "No matching rule for the new flow, ignore it.");
            continue;
        }
        SPDLOG_LOGGER_DEBUG(logger, "New flow detected, adding to flow table and sending SYN to backend server. Selected backend index: {}",
                            static_cast<int>(rule->d_index));
        _get_inbound_syn_pkt(recv_mbufs[i], rule->d_index, send_mbufs[num_send_pkts]);
        num_send_pkts++;
        flow_data = new MiresgaFlowData_t;
        flow_data->state = FlowState_t::BACKEND_SYN;
        flow_data->entry_data.key = src_oft_key;
        flow_data->entry_data.data.d_index = rule->d_index;
        flow_data->entry_data.data.flow_state = rule->offload_flag == 1 ? static_cast<uint8_t>(FlowState_t::OFFLOAD) : static_cast<uint8_t>(FlowState_t::ESTABLISHED);
        // Cache the received packet for later use.
        flow_data->recv_pkt = new char[recv_mbufs[i]->data_len];
        flow_data->recv_pkt_size = recv_mbufs[i]->data_len;
        memcpy(flow_data->recv_pkt, rte_pktmbuf_mtod(recv_mbufs[i], char*), recv_mbufs[i]->data_len);
        _flow_table->insert_flow(src_oft_key, flow_data);
    }
    if (likely(num_send_pkts > 0)) {
        SPDLOG_LOGGER_DEBUG(logger, "Sending {} packets", num_send_pkts);
        _send_pkts(send_mbufs, num_send_pkts);
    }
    rte_pktmbuf_free_bulk(send_mbufs + num_send_pkts, (nb_pkts << 1) - num_send_pkts);
}

void 
PktProcessor::_main_loop() {
    SPDLOG_LOGGER_DEBUG(logger, "Entering main loop");
    rte_mbuf* recv_mbufs[_dpdk_manager->dpdk_config->burst_size];
    while(!_exit_flag) {
        uint16_t nb_pkts = rte_eth_rx_burst(_dpdk_manager->port_id, _queue_id, recv_mbufs, _dpdk_manager->dpdk_config->burst_size);
        if (unlikely(nb_pkts < 0)) {
            SPDLOG_LOGGER_ERROR(logger, "Error receiving packets");
            throw std::runtime_error("Error receiving packets");
        }
        if (likely(nb_pkts > 0)) {
            SPDLOG_LOGGER_DEBUG(logger, "Received {} packets", nb_pkts);
            _process_pkts(recv_mbufs, nb_pkts);
            rte_pktmbuf_free_bulk(recv_mbufs, nb_pkts);
        }
    }
    SPDLOG_LOGGER_DEBUG(logger, "Exiting main loop");
}

int 
PktProcessor::_worker_fun_wrapper(
    void* arg
) {
    PktProcessor* processor = static_cast<PktProcessor*>(arg);
    processor->_main_loop();
    return 0;
}

void PktProcessor::start(int core_id) {
    SPDLOG_LOGGER_DEBUG(logger, "Starting packet processor on core {}", core_id);
    _exit_flag = false;
    if (rte_eal_remote_launch(&PktProcessor::_worker_fun_wrapper, this, core_id) != 0) {
        throw std::runtime_error("Failed to launch packet processor thread.");
    }
}

void PktProcessor::stop() {
    _exit_flag = true;
}
