#include "pkt_processor.h"

const uint8_t crc8_table[256] = {
    0x00, 0x07, 0x0E, 0x09, 0x1C, 0x1B, 0x12, 0x15, 0x38, 0x3F, 0x36, 0x31, 0x24, 0x23, 0x2A, 0x2D, 
    0x70, 0x77, 0x7E, 0x79, 0x6C, 0x6B, 0x62, 0x65, 0x48, 0x4F, 0x46, 0x41, 0x54, 0x53, 0x5A, 0x5D, 
    0xE0, 0xE7, 0xEE, 0xE9, 0xFC, 0xFB, 0xF2, 0xF5, 0xD8, 0xDF, 0xD6, 0xD1, 0xC4, 0xC3, 0xCA, 0xCD, 
    0x90, 0x97, 0x9E, 0x99, 0x8C, 0x8B, 0x82, 0x85, 0xA8, 0xAF, 0xA6, 0xA1, 0xB4, 0xB3, 0xBA, 0xBD, 
    0xC7, 0xC0, 0xC9, 0xCE, 0xDB, 0xDC, 0xD5, 0xD2, 0xFF, 0xF8, 0xF1, 0xF6, 0xE3, 0xE4, 0xED, 0xEA, 
    0xB7, 0xB0, 0xB9, 0xBE, 0xAB, 0xAC, 0xA5, 0xA2, 0x8F, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9D, 0x9A, 
    0x27, 0x20, 0x29, 0x2E, 0x3B, 0x3C, 0x35, 0x32, 0x1F, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0D, 0x0A, 
    0x57, 0x50, 0x59, 0x5E, 0x4B, 0x4C, 0x45, 0x42, 0x6F, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7D, 0x7A, 
    0x89, 0x8E, 0x87, 0x80, 0x95, 0x92, 0x9B, 0x9C, 0xB1, 0xB6, 0xBF, 0xB8, 0xAD, 0xAA, 0xA3, 0xA4, 
    0xF9, 0xFE, 0xF7, 0xF0, 0xE5, 0xE2, 0xEB, 0xEC, 0xC1, 0xC6, 0xCF, 0xC8, 0xDD, 0xDA, 0xD3, 0xD4, 
    0x69, 0x6E, 0x67, 0x60, 0x75, 0x72, 0x7B, 0x7C, 0x51, 0x56, 0x5F, 0x58, 0x4D, 0x4A, 0x43, 0x44, 
    0x19, 0x1E, 0x17, 0x10, 0x05, 0x02, 0x0B, 0x0C, 0x21, 0x26, 0x2F, 0x28, 0x3D, 0x3A, 0x33, 0x34, 
    0x4E, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5C, 0x5B, 0x76, 0x71, 0x78, 0x7F, 0x6A, 0x6D, 0x64, 0x63, 
    0x3E, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2C, 0x2B, 0x06, 0x01, 0x08, 0x0F, 0x1A, 0x1D, 0x14, 0x13, 
    0xAE, 0xA9, 0xA0, 0xA7, 0xB2, 0xB5, 0xBC, 0xBB, 0x96, 0x91, 0x98, 0x9F, 0x8A, 0x8D, 0x84, 0x83, 
    0xDE, 0xD9, 0xD0, 0xD7, 0xC2, 0xC5, 0xCC, 0xCB, 0xE6, 0xE1, 0xE8, 0xEF, 0xFA, 0xFD, 0xF4, 0xF3
};

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

PktProcessor::PktProcessor(int queue_id, int socket_id) 
    : _exit_flag(false), _queue_id(queue_id), _socket_id(socket_id),
      _dpdk_manager(DPDKManager::get_instance()),
      _rule_manager(RuleManager::get_instance()),
      _rdma_manager(RDMAManager::get_instance()),
      _entry_manager(EntryManager::get_instance()),
      _flow_table(FlowTable::get_instance()),
      _add_token(_entry_manager->get_add_queue_token()),
      _del_token(_entry_manager->get_del_queue_token())
{}

PktProcessor::~PktProcessor() {
    stop();
}

uint8_t PktProcessor::_calc_crc8(uint32_t ip, uint16_t port) {
    uint8_t crc = 0;
    crc = crc8_table[crc ^ (ip & 0xff)];
    crc = crc8_table[crc ^ ((ip >> 8) & 0xff)];
    crc = crc8_table[crc ^ ((ip >> 16) & 0xff)];
    crc = crc8_table[crc ^ ((ip >> 24) & 0xff)];
    crc = crc8_table[crc ^ (port & 0xff)];
    crc = crc8_table[crc ^ (port >> 8)];
    return crc;
}

std::string PktProcessor::_parse_payload(std::string payload) {
    // We provide a simple parsing function here. Users can modify it to fit their own payload format.
    // We assume we use the url path in HTTP GET request as the payload.
    size_t pos1 = payload.find("/");
    if (pos1 == std::string::npos) return "";
    pos1++;
    size_t pos2 = payload.find(" ", pos1);
    if (pos2 == std::string::npos) return "";
    return payload.substr(pos1, pos2 - pos1);
}

MiresgaStatus_t PktProcessor::_send_pkts(rte_mbuf** mbuf, size_t nb_pkts) {
    uint16_t nb_tx = rte_eth_tx_burst(_dpdk_manager->port_id, _queue_id, mbuf, nb_pkts);
    MiresgaStatus_t status = MiresgaStatus_t::OK;
    if (nb_tx != nb_pkts) {
        status = MiresgaStatus_t::INTERNAL_ERROR;
    }
    rte_pktmbuf_free_bulk(mbuf + nb_tx, nb_pkts - nb_tx);
    return status;
}

void PktProcessor::_get_inbound_normal_pkt(rte_mbuf* recv_mbuf, uint8_t d_index, rte_mbuf* send_mbuf) {
    void* recv_pkt_data = rte_pktmbuf_mtod(recv_mbuf, void*);
    rte_ether_hdr* send_eth_hdr = rte_pktmbuf_mtod(send_mbuf, rte_ether_hdr*);
    rte_ipv4_hdr* send_ip_hdr = (rte_ipv4_hdr*)(send_eth_hdr + 1);
    rte_tcp_hdr* send_tcp_hdr = (rte_tcp_hdr*)(send_ip_hdr + 1);
    memcpy(send_eth_hdr, recv_pkt_data, recv_mbuf->data_len);
    ServerInfo_t* server_info = nullptr;
    if(_rule_manager->get_backend_server_info(d_index, &server_info) != MiresgaStatus_t::OK) {
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

void PktProcessor::_get_outbound_normal_pkt(rte_mbuf* recv_mbuf, rte_mbuf* send_mbuf) {
    void* recv_pkt_data = rte_pktmbuf_mtod(recv_mbuf, void*);
    rte_ether_hdr* send_eth_hdr = rte_pktmbuf_mtod(send_mbuf, rte_ether_hdr*);
    rte_ipv4_hdr* send_ip_hdr = (rte_ipv4_hdr*)(send_eth_hdr + 1);
    rte_tcp_hdr* send_tcp_hdr = (rte_tcp_hdr*)(send_ip_hdr + 1);
    memcpy(send_eth_hdr, recv_pkt_data, recv_mbuf->data_len);
    ServerInfo_t* virtual_server_info = nullptr;
    if(_rule_manager->get_virtual_server_info(&virtual_server_info) != MiresgaStatus_t::OK) {
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

void PktProcessor::_get_inbound_syn_pkt(rte_mbuf* recv_mbuf, uint8_t d_index, rte_mbuf* send_mbuf) {
    void* recv_pkt_data = rte_pktmbuf_mtod(recv_mbuf, void*);
    rte_ether_hdr* send_eth_hdr = rte_pktmbuf_mtod(send_mbuf, rte_ether_hdr*);
    rte_ipv4_hdr* send_ip_hdr = (rte_ipv4_hdr*)(send_eth_hdr + 1);
    rte_tcp_hdr* send_tcp_hdr = (rte_tcp_hdr*)(send_ip_hdr + 1);
    memcpy(send_eth_hdr, recv_pkt_data, sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_tcp_hdr) + sizeof(option_char));
    ServerInfo_t* server_info = nullptr;
    if(_rule_manager->get_backend_server_info(d_index, &server_info) != MiresgaStatus_t::OK) {
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

void PktProcessor::_get_inbound_rst_pkt(rte_mbuf* recv_mbuf, uint8_t d_index, rte_mbuf* send_mbuf) {
    void* recv_pkt_data = rte_pktmbuf_mtod(recv_mbuf, void*);
    rte_ether_hdr* send_eth_hdr = rte_pktmbuf_mtod(send_mbuf, rte_ether_hdr*);
    rte_ipv4_hdr* send_ip_hdr = (rte_ipv4_hdr*)(send_eth_hdr + 1);
    rte_tcp_hdr* send_tcp_hdr = (rte_tcp_hdr*)(send_ip_hdr + 1);
    memcpy(send_eth_hdr, recv_pkt_data, sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_tcp_hdr));
    ServerInfo_t* server_info = nullptr;
    if(_rule_manager->get_backend_server_info(d_index, &server_info) != MiresgaStatus_t::OK) {
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

void PktProcessor::_get_outbound_rst_pkt(rte_mbuf* recv_mbuf, rte_mbuf* send_mbuf) {
    void* recv_pkt_data = rte_pktmbuf_mtod(recv_mbuf, void*);
    rte_ether_hdr* send_eth_hdr = rte_pktmbuf_mtod(send_mbuf, rte_ether_hdr*);
    rte_ipv4_hdr* send_ip_hdr = (rte_ipv4_hdr*)(send_eth_hdr + 1);
    rte_tcp_hdr* send_tcp_hdr = (rte_tcp_hdr*)(send_ip_hdr + 1);
    memcpy(send_eth_hdr, recv_pkt_data, sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_tcp_hdr));
    ServerInfo_t* virtual_server_info = nullptr;
    if(_rule_manager->get_virtual_server_info(&virtual_server_info) != MiresgaStatus_t::OK) {
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

void PktProcessor::_get_cached_pkt(char* cached_pkt, uint16_t cached_pkt_len, 
                                   uint8_t d_index, rte_mbuf* send_mbuf) {
    rte_ether_hdr* send_eth_hdr = rte_pktmbuf_mtod(send_mbuf, rte_ether_hdr*);
    rte_ipv4_hdr* send_ip_hdr = (rte_ipv4_hdr*)(send_eth_hdr + 1);
    rte_tcp_hdr* send_tcp_hdr = (rte_tcp_hdr*)(send_ip_hdr + 1);
    memcpy(send_eth_hdr, cached_pkt, cached_pkt_len);
    ServerInfo_t* server_info = nullptr;
    if(_rule_manager->get_backend_server_info(d_index, &server_info) != MiresgaStatus_t::OK) {
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

void PktProcessor::_process_pkts(rte_mbuf** recv_mbufs, uint16_t nb_pkts) {
    rte_mbuf* send_mbufs[(nb_pkts << 1)];
    size_t num_send_pkts = 0;
    if (rte_pktmbuf_alloc_bulk(_dpdk_manager->mbuf_pool, send_mbufs, nb_pkts << 1) != 0) {
        return;
    }
    for (int i = 0; i < nb_pkts; ++i) {
        uint16_t header_size = 0;
        uint32_t payload_len = 0;
        rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(recv_mbufs[i], rte_ether_hdr*);
        if (eth_hdr->ether_type != htons(RTE_ETHER_TYPE_IPV4)) {
            continue;
        }
        rte_ipv4_hdr* ip_hdr = (rte_ipv4_hdr*)(eth_hdr + 1);
        header_size += (ip_hdr->version_ihl & 0x0f) << 2;
        if (ip_hdr->next_proto_id != IPPROTO_TCP) {
            continue;
        }
        rte_tcp_hdr* tcp_hdr = (rte_tcp_hdr*)((char*)ip_hdr + header_size);
        header_size += (tcp_hdr->data_off >> 4) * 4;
        payload_len = ntohs(ip_hdr->total_length) - header_size;
        uint8_t src_crc = _calc_crc8(ntohl(ip_hdr->src_addr), ntohs(tcp_hdr->src_port));
        uint8_t dst_crc = _calc_crc8(ntohl(ip_hdr->dst_addr), ntohs(tcp_hdr->dst_port));
        MiresgaOFTKey_t src_oft_key = {0, src_crc, ip_hdr->src_addr, tcp_hdr->src_port};
        MiresgaOFTKey_t dst_oft_key = {0, dst_crc, ip_hdr->dst_addr, tcp_hdr->dst_port};
        MiresgaFlowData_t* flow_data = _flow_table->get_flow(src_oft_key);
        if (flow_data != nullptr) {
            // Process inbound.
            if (tcp_hdr->tcp_flags & RTE_TCP_RST_FLAG) {
            // Handle connection termination.
                if (flow_data->state == FlowState_t::OFFLOAD) {
                    // Remove the entry from the offload table.
                    _entry_manager->del_entry(_del_token, src_oft_key);
                }
                if (flow_data->state >= FlowState_t::BACKEND_SYN) {
                    // Release the backend server.
                    _get_inbound_rst_pkt(recv_mbufs[i], flow_data->entry_data.data.d_index, send_mbufs[num_send_pkts]);
                    num_send_pkts++;
                    _rdma_manager->del_flow_data(&src_oft_key);
                }
                _flow_table->remove_flow(src_oft_key);
            }
            else if(tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG) {
                _get_outbound_rst_pkt(recv_mbufs[i], send_mbufs[num_send_pkts]);
                num_send_pkts++;
                if (flow_data->state == FlowState_t::OFFLOAD) {
                    // Remove the entry from the offload table.
                    _entry_manager->del_entry(_del_token, src_oft_key);
                }
                if (flow_data->state >= FlowState_t::BACKEND_SYN) {
                    // Release the backend server.
                    _get_inbound_rst_pkt(recv_mbufs[i], flow_data->entry_data.data.d_index, send_mbufs[num_send_pkts]);
                    num_send_pkts++;
                    _rdma_manager->del_flow_data(&src_oft_key);
                }
                _flow_table->remove_flow(src_oft_key);
            }
            else {
                switch(flow_data->state) {
                    case FlowState_t::ESTABLISHED:
                    case FlowState_t::OFFLOAD: {
                        if (payload_len > 0) {
                            // Recieve new payload, parse it and check if we need to change the backend server.
                            std::string payload((char*)tcp_hdr + (tcp_hdr->data_off >> 4) * 4, 
                                                payload_len);
                            // Note: Here is an simple example. Users may implement more complex payload parsing logic here.
                            std::string parsed_payload = _parse_payload(payload);
                            RuleEntry_t* rule = nullptr;
                            if (_rule_manager->get_rule(parsed_payload, &rule) != MiresgaStatus_t::OK) {
                                break;
                            }
                            // Backend server changed. Send RST to the old backend server and SYN to the new backend server.
                            if (rule->d_index != flow_data->entry_data.data.d_index) {
                                _get_inbound_rst_pkt(recv_mbufs[i], flow_data->entry_data.data.d_index, send_mbufs[num_send_pkts]);
                                num_send_pkts++;
                                if (flow_data->state == FlowState_t::OFFLOAD) {
                                    _entry_manager->del_entry(_del_token, src_oft_key);
                                }
                                _get_inbound_syn_pkt(recv_mbufs[i], rule->d_index, send_mbufs[num_send_pkts]);
                                num_send_pkts++;
                                flow_data->entry_data.data.d_index = rule->d_index;
                                flow_data->entry_data.data.flow_state = rule->offload_flag == 1 ? static_cast<uint8_t>(FlowState_t::OFFLOAD) : static_cast<uint8_t>(FlowState_t::BACKEND_SYN);
                                flow_data->state = FlowState_t::BACKEND_SYN;
                                if (flow_data->recv_pkt != nullptr) {
                                    rte_free(flow_data->recv_pkt);
                                }
                                flow_data->recv_pkt = (char*)rte_malloc_socket("recv_pkt", recv_mbufs[i]->data_len, 0, _socket_id);
                                flow_data->recv_pkt_size = recv_mbufs[i]->data_len;
                                memcpy(flow_data->recv_pkt, rte_pktmbuf_mtod(recv_mbufs[i], char*), recv_mbufs[i]->data_len);
                            }
                            // Backend server not changed. Just forward the packet.
                            else {
                                _get_inbound_normal_pkt(recv_mbufs[i], flow_data->entry_data.data.d_index, send_mbufs[num_send_pkts]);
                                num_send_pkts++;
                                if (flow_data->state == FlowState_t::OFFLOAD && rule->offload_flag == 0) {
                                    flow_data->entry_data.data.flow_state = static_cast<uint8_t>(FlowState_t::ESTABLISHED);
                                    _entry_manager->del_entry(_del_token, src_oft_key);
                                    flow_data->state = FlowState_t::ESTABLISHED;
                                }
                                else if (flow_data->state == FlowState_t::ESTABLISHED && rule->offload_flag == 1) {
                                    flow_data->entry_data.data.flow_state = static_cast<uint8_t>(FlowState_t::OFFLOAD);
                                    _entry_manager->add_entry(_add_token, flow_data->entry_data);
                                    flow_data->state = FlowState_t::OFFLOAD;
                                }
                            }
                            _rdma_manager->add_flow_data(&flow_data->entry_data);
                        }
                        else {
                            _get_inbound_normal_pkt(recv_mbufs[i], flow_data->entry_data.data.d_index, send_mbufs[num_send_pkts]);
                            num_send_pkts++;
                        }
                        break;
                    }
                    case FlowState_t::BACKEND_SYN: {
                        if (flow_data->recv_pkt != nullptr) {
                            rte_ether_hdr *recv_ether_hdr = (rte_ether_hdr *)flow_data->recv_pkt;
                            rte_ipv4_hdr *recv_ip_hdr = (rte_ipv4_hdr *)(recv_ether_hdr + 1);
                            rte_tcp_hdr *recv_tcp_hdr = (rte_tcp_hdr *)(recv_ip_hdr + 1);
                            if (recv_tcp_hdr->sent_seq == tcp_hdr->sent_seq)
                            {
                                _get_inbound_syn_pkt(recv_mbufs[i], flow_data->entry_data.data.d_index, send_mbufs[num_send_pkts]);
                                num_send_pkts++;
                            }
                        }
                        break;
                    }
                    default:
                        break;
                }
            }
            continue;
        }
        flow_data = _flow_table->get_flow(dst_oft_key);
        if (flow_data != nullptr) {
            // Process outbound.
            if (tcp_hdr->tcp_flags & RTE_TCP_RST_FLAG) {
            // Handle connection termination.
                if (flow_data->state == FlowState_t::OFFLOAD) {
                    // Remove the entry from the offload table.
                    _entry_manager->del_entry(_del_token, src_oft_key);
                }
                _rdma_manager->del_flow_data(&src_oft_key);
                // Send RST to the client.
                _get_outbound_normal_pkt(recv_mbufs[i], send_mbufs[num_send_pkts]);
                num_send_pkts++;
                _flow_table->remove_flow(src_oft_key);
            }
            else if(tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG) {
                // Send RST to the client.
                _get_outbound_rst_pkt(recv_mbufs[i], send_mbufs[num_send_pkts]);
                num_send_pkts++;
                // Send RST to the backend server.
                _get_inbound_rst_pkt(recv_mbufs[i], flow_data->entry_data.data.d_index, send_mbufs[num_send_pkts + 1]);
                num_send_pkts++;
                if (flow_data->state == FlowState_t::OFFLOAD) {
                    // Remove the entry from the offload table.
                    _entry_manager->del_entry(_del_token, src_oft_key);
                }
                _rdma_manager->del_flow_data(&src_oft_key);
                _flow_table->remove_flow(src_oft_key);
            }
            else
            {
                switch(flow_data->state) {
                    case FlowState_t::BACKEND_SYN:
                    {
                        if (tcp_hdr->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG) == 0) {
                            break;
                        }
                        if (flow_data->entry_data.data.flow_state == static_cast<uint8_t>(FlowState_t::OFFLOAD)) {
                            _entry_manager->add_entry(_add_token, flow_data->entry_data);
                            flow_data->state = FlowState_t::OFFLOAD;
                        }
                        else {
                            flow_data->state = FlowState_t::ESTABLISHED;
                        }
                        _get_cached_pkt(static_cast<char*>(flow_data->recv_pkt), flow_data->recv_pkt_size, flow_data->entry_data.data.d_index, send_mbufs[num_send_pkts]);
                        ++num_send_pkts;
                        break;
                    }
                    case FlowState_t::OFFLOAD:
                    case FlowState_t::ESTABLISHED:
                    {
                        _get_outbound_normal_pkt(recv_mbufs[i], send_mbufs[num_send_pkts]);
                        num_send_pkts++;
                        break;
                    }
                    default:
                        break;
                }
            }
            continue;
        }
        // Process new flow.
        if (payload_len == 0) {
            continue;
        }
        std::string payload((char*)tcp_hdr + (tcp_hdr->data_off >> 4) * 4, 
                            payload_len);
        // Note: Here is an simple example. Users may implement more complex payload parsing logic here.
        std::string parsed_payload = _parse_payload(payload);
        RuleEntry_t* rule = nullptr;
        if (_rule_manager->get_rule(parsed_payload, &rule) != MiresgaStatus_t::OK) {
            continue;
        }
        _get_inbound_syn_pkt(recv_mbufs[i], rule->d_index, send_mbufs[num_send_pkts]);
        num_send_pkts++;
        flow_data = static_cast<MiresgaFlowData_t*>(rte_malloc_socket("flow_data", sizeof(MiresgaFlowData_t), 0, _socket_id));
        flow_data->state = FlowState_t::BACKEND_SYN;
        flow_data->entry_data.key = src_oft_key;
        flow_data->entry_data.data.d_index = rule->d_index;
        flow_data->entry_data.data.flow_state = rule->offload_flag == 1 ? static_cast<uint8_t>(FlowState_t::OFFLOAD) : static_cast<uint8_t>(FlowState_t::BACKEND_SYN);
        flow_data->recv_pkt = static_cast<char*>(rte_malloc_socket("recv_pkt", recv_mbufs[i]->data_len, 0, _socket_id));
        flow_data->recv_pkt_size = recv_mbufs[i]->data_len;
        memcpy(flow_data->recv_pkt, rte_pktmbuf_mtod(recv_mbufs[i], char*), recv_mbufs[i]->data_len);
        _flow_table->insert_flow(src_oft_key, flow_data);
    }
    if (num_send_pkts > 0) {
        _send_pkts(send_mbufs, num_send_pkts);
    }
}

void PktProcessor::_main_loop() {
    rte_mbuf* recv_mbufs[_dpdk_manager->dpdk_config->burst_size];
    while(!_exit_flag) {
        uint16_t nb_pkts = rte_eth_rx_burst(_dpdk_manager->port_id, _queue_id, recv_mbufs, _dpdk_manager->dpdk_config->burst_size);
        if (nb_pkts > 0) {
            _process_pkts(recv_mbufs, nb_pkts);
            rte_pktmbuf_free_bulk(recv_mbufs, nb_pkts);
        }
    }
}

int PktProcessor::_worker_fun_wrapper(void* arg) {
    PktProcessor* processor = static_cast<PktProcessor*>(arg);
    processor->_main_loop();
    return 0;
}

void PktProcessor::start(int core_id) {
    _exit_flag = false;
    if (rte_eal_remote_launch(&PktProcessor::_worker_fun_wrapper, this, core_id) != 0) {
        throw std::runtime_error("Failed to launch packet processor thread.");
    }
}

void PktProcessor::stop() {
    _exit_flag = true;
    uint32_t core_id;
    RTE_LCORE_FOREACH_WORKER(core_id) {
        rte_eal_wait_lcore(core_id);
    }
}
