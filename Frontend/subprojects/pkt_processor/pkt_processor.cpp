#include "pkt_processor.hpp"


std::vector<uint8_t> pkt_processor_t::crc8_table(256);
libcuckoo::cuckoohash_map<uint64_t, flow_data_t *> *pkt_processor_t::flow_hash_map = nullptr;
rte_mempool *pkt_processor_t::mbuf_pool = nullptr;
moodycamel::ConcurrentQueue<my_pair_t> *pkt_processor_t::add_queue = nullptr;
moodycamel::ConcurrentQueue<my_key_t> *pkt_processor_t::del_queue = nullptr;
uint16_t pkt_processor_t::port_id = 0;
rule_controller_t *pkt_processor_t::rule_controller = nullptr;
dpdk_config_t *pkt_processor_t::dpdk_config = nullptr;

pkt_processor_t::pkt_processor_t(int queue_id):add_token(*add_queue), del_token(*del_queue) {
    this->queue_id = queue_id;
    exit_flag = true;
    status = status_t::INTERNAL_ERROR;
}

uint8_t pkt_processor_t::calculate_crc8(uint32_t ip, uint16_t port) {
    uint8_t crc = 0;
    crc = crc8_table[crc ^ (ip & 0xff)];
    crc = crc8_table[crc ^ ((ip >> 8) & 0xff)];
    crc = crc8_table[crc ^ ((ip >> 16) & 0xff)];
    crc = crc8_table[crc ^ ((ip >> 24) & 0xff)];
    crc = crc8_table[crc ^ (port & 0xff)];
    crc = crc8_table[crc ^ (port >> 8)];
    return crc;
}

// This function should be customized.
char *pkt_processor_t::parse_payload(char *payload, int payload_size, int &size) {
    size = -1;
    int i = 0;
    while(i < payload_size && payload[i] != '/') {
        ++i;
    }
    ++i;
    char *res = payload + i;
    size = 0;
    while(i < payload_size && payload[i] != ' ' && payload[i] != '\r') {
        ++i;
        ++size;
    }
    return res;
}


status_t pkt_processor_t::process_pkts(rte_mbuf **recv_pkts, size_t pkt_num) {
    #ifdef DEBUG 
    std::cout << pkt_num << " packets received" << std::endl;
    #endif
    rte_mbuf *send_pkts[2 * pkt_num];
    size_t send_size = 0;
    if(rte_pktmbuf_alloc_bulk(mbuf_pool, send_pkts, 2 * pkt_num) != 0) {
        return status_t::INTERNAL_ERROR;
    }
    status_t status = status_t::OK;
    size_t send_pkt_num = 0;
    char url_copy[20];
    for(int i = 0; i < pkt_num; ++i) {
        uint16_t header_size = 0;
        bool payload_flag = false;
        rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(recv_pkts[i], rte_ether_hdr*);
        if(eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
            printf("[ERROR]: Receive a non-ipv4 packet.\n");
            continue;
        }
        rte_ipv4_hdr* ip_hdr = (rte_ipv4_hdr*)(eth_hdr + 1);
        if(ip_hdr->next_proto_id != IPPROTO_TCP) {
            printf("[ERROR]: Receive a non-TCP packet.\n");
            continue;
        }
        rte_tcp_hdr* tcp_hdr = (rte_tcp_hdr*)(ip_hdr + 1);
        header_size = 20 + (tcp_hdr->data_off >> 4) * 4;
        if(header_size < ntohs(ip_hdr->total_length)) {
            payload_flag = true;
        }
        uint8_t src_crc = pkt_processor_t::calculate_crc8(ip_hdr->src_addr, tcp_hdr->src_port);
        uint8_t dst_crc = pkt_processor_t::calculate_crc8(ip_hdr->dst_addr, tcp_hdr->dst_port);
        uint64_t src_key = ((uint64_t)ip_hdr->src_addr << 32) + tcp_hdr->src_port;
        uint64_t dst_key = ((uint64_t)ip_hdr->dst_addr << 32) + tcp_hdr->dst_port;
        my_key_t src_my_key = {src_crc, htonl(ip_hdr->src_addr), htons(tcp_hdr->src_port)};
        my_key_t dst_my_key = {dst_crc, htonl(ip_hdr->dst_addr), htons(tcp_hdr->dst_port)};
        flow_data_t *flow_data = nullptr;
        if(pkt_processor_t::flow_hash_map[src_crc].find(src_key, flow_data)) {
            // #ifdef DEBUG
            // std::cout << "Find a src flow data, state: " << flow_data->state << std::endl;
            // #endif
            switch(flow_data->state) {
                case(COMPLETE): 
                case(OFFLOAD):
                    if(tcp_hdr->tcp_flags & RTE_TCP_RST_FLAG) {
                        // #ifdef DEBUG
                        // std::cout << "Receive a rst packet.\n" << std::endl;
                        // #endif
                        status = forward_inbound_pkt(flow_data->entry_data.d_index, recv_pkts[i], send_pkts[send_size]);
                        if(status != status_t::OK) {
                            std::cout << "Failed to forward inbound pkt.\n" << std::endl;
                            return status;
                        }
                        ++send_size;
                        if(flow_data->state == OFFLOAD) {
                            pkt_processor_t::del_queue->enqueue(del_token, src_my_key);
                        }
                        pkt_processor_t::flow_hash_map[src_crc].erase(src_key);
                        if(flow_data->recv_pkt) {
                            rte_free(flow_data->recv_pkt);
                        }
                        rte_free(flow_data);
                        continue;
                    }
                    if(tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG) {
                        // #ifdef DEBUG
                        // std::cout << "Receive a fin packet.\n" << std::endl;
                        // #endif
                        status = reply_rst_pkt(recv_pkts[i], send_pkts[send_size]);
                        if(status != status_t::OK) {
                            std::cout << "Failed to reply rst pkt.\n" << std::endl;
                            return status;
                        }
                        ++send_size;
                        tcp_hdr->tcp_flags = RTE_TCP_RST_FLAG;
                        status = forward_inbound_pkt(flow_data->entry_data.d_index, recv_pkts[i], send_pkts[send_size]);
                        if(status != status_t::OK) {
                            std::cout << "Failed to forward inbound pkt.\n" << std::endl;
                            return status;
                        }
                        ++send_size;
                        if(flow_data->state == OFFLOAD) {
                            pkt_processor_t::del_queue->enqueue(del_token, src_my_key);
                        }
                        pkt_processor_t::flow_hash_map[src_crc].erase(src_key);
                        if(flow_data->recv_pkt) {
                            rte_free(flow_data->recv_pkt);
                        }
                        rte_free(flow_data);
                        continue;
                    }
                    if(payload_flag) {
                        char *payload = (char*)((void*)tcp_hdr + (tcp_hdr->data_off >> 4) * 4);
                        int size = 0;
                        char *url = parse_payload(payload, ntohs(ip_hdr->total_length) - header_size, size);
                        if(size == -1) {
                            #ifdef DEBUG
                            std::cout << "[ERROR]: Receive a packet without url.\n";
                            #endif
                            continue;
                        }
                        rte_memcpy(url_copy, url, size);
                        url_copy[size] = '\0';
                        my_data_t *new_data;
                        if((new_data = pkt_processor_t::rule_controller->lookup_balancing_rule(url_copy)) != nullptr) {
                            if(new_data->d_index != flow_data->entry_data.d_index) {
                                if(send_rst_pkt(flow_data->entry_data.d_index, recv_pkts[i], send_pkts[send_size]) != OK) {
                                    std::cout << "Failed to send RST pkt.\n" << std::endl;
                                    status = status_t::INTERNAL_ERROR;
                                    return status;
                                }
                                ++send_size;
                                if(flow_data->state == OFFLOAD) {
                                   pkt_processor_t::del_queue->enqueue(del_token, src_my_key);
                                }
                                if(send_syn_pkt(new_data->d_index, recv_pkts[i], send_pkts[send_size]) != OK) {
                                    std::cout << "Failed to send SYN pkt.\n" << std::endl;
                                    status = status_t::INTERNAL_ERROR;
                                    return status;
                                }
                                send_size++;
                                flow_data->state = BACKEND_SYN;
                                flow_data->entry_data = *new_data;
                                if (flow_data->recv_pkt) {
                                    rte_free(flow_data->recv_pkt);
                                }
                                flow_data->recv_pkt = (char*)rte_malloc("recv_pkt", recv_pkts[i]->data_len, 0);
                                flow_data->pkt_size = recv_pkts[i]->data_len;
                                memcpy(flow_data->recv_pkt, (void*)eth_hdr, recv_pkts[i]->data_len);
                            }
                            else {
                                if((status = forward_inbound_pkt(flow_data->entry_data.d_index, recv_pkts[i], send_pkts[send_size])) != OK) {
                                    std::cout << "Failed to forward inbound pkt.\n" << std::endl; 
                                    return status;
                                }
                                send_size++;
                                if(flow_data->state == COMPLETE && new_data->offload_flag == 1) {
                                    flow_data->state = OFFLOAD;
                                    my_pair_t new_pair;
                                    new_pair.key = src_my_key;
                                    new_pair.data = flow_data->entry_data;
                                    pkt_processor_t::add_queue->enqueue(add_token, new_pair);
                                }
                                else if(flow_data->state == OFFLOAD && new_data->offload_flag == 0) {
                                    flow_data->state = COMPLETE;
                                    pkt_processor_t::del_queue->enqueue(del_token, src_my_key);
                                }
                            }
                        }
                        #ifdef DEBUG
                        else {
                            printf("[ERROR]: No balancing rule found.\n");
                        }
                        #endif


                        continue;
                    }
                    if((status = forward_inbound_pkt(flow_data->entry_data.d_index, recv_pkts[i], send_pkts[send_size])) != OK) {
                        std::cout << "Failed to forward inbound pkt.\n" << std::endl;
                        return status;
                    }
                    ++send_size;
                    continue;
                case(BACKEND_SYN): {
                    if((tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG) || (tcp_hdr->tcp_flags & RTE_TCP_RST_FLAG)) {
                        if((status = reply_rst_pkt(recv_pkts[i], send_pkts[send_size])) != OK) {
                            std::cout << "Failed to reply RST pkt.\n" << std::endl;
                            return status;
                        }
                        ++send_size;
                        if(flow_data->recv_pkt) {
                            rte_free(flow_data->recv_pkt);
                        }
                        rte_free(flow_data);
                        continue;
                    }
                    if(flow_data->recv_pkt) {
                        rte_ether_hdr *recv_ether_hdr = (rte_ether_hdr *)flow_data->recv_pkt;
                        rte_ipv4_hdr *recv_ip_hdr = (rte_ipv4_hdr *)(recv_ether_hdr + 1);
                        rte_tcp_hdr *recv_tcp_hdr = (rte_tcp_hdr *)(recv_ip_hdr + 1);
                        if(recv_tcp_hdr->sent_seq == tcp_hdr->sent_seq) {
                            if((status = send_syn_pkt(flow_data->entry_data.d_index, recv_pkts[i], send_pkts[send_size])) != OK) {
                                std::cout << "Failed to send SYN pkt.\n" << std::endl;
                                return status;
                            }
                            ++send_size;
                        }
                    }
                    continue;
                }
                // default: {
                //     std::cout << "[ERROR]: Receive a packet with invalid state: " << flow_data->state << std::endl;
                //     continue;
                // }
            }
        }
        if(pkt_processor_t::flow_hash_map[dst_crc].find(dst_key, flow_data)) {
            // #ifdef DEBUG
            // std::cout << "Find a dst flow data" << std::endl;
            // #endif
            switch(flow_data->state) {
                case(BACKEND_SYN): {
                    if(tcp_hdr->tcp_flags != (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG)) {
                        //std::cout << "[ERROR]: Receive a packet with invalid flags: " << std::hex << (int)tcp_hdr->tcp_flags << std::dec << std::endl;
                        continue;
                    }
                    // #ifdef DEBUG
                    // std::cout << "Receive a syn-ack packet.\n" << std::endl;
                    // #endif
                    my_pair_t new_pair;
                    new_pair.key = dst_my_key;
                    new_pair.data = flow_data->entry_data;
                    if(flow_data->entry_data.offload_flag == 1) {
                        flow_data->state = OFFLOAD;
                        pkt_processor_t::add_queue->enqueue(add_token, new_pair);
                    }
                    else {
                        flow_data->state = COMPLETE;
                    }
                    //std::cout << flow_data->state << std::endl;
                    if((status = send_cached_pkt(flow_data->entry_data.d_index, flow_data->recv_pkt, send_pkts[send_size], flow_data->pkt_size)) != OK) {
                        std::cout << "Failed to send cached pkt.\n" << std::endl;
                        return status;
                    }
                    ++send_size;
                    continue;
                }
                case(COMPLETE):
                case(OFFLOAD): {
                    if(tcp_hdr->tcp_flags & RTE_TCP_RST_FLAG) {
                        status = forward_outbound_pkt(recv_pkts[i], send_pkts[send_size]);
                        if(status != status_t::OK) {
                            std::cout << "Failed to forward outbound pkt.\n" << std::endl;
                            return status;
                        }
                        ++send_size;
                        if(flow_data->state == OFFLOAD) {
                            pkt_processor_t::del_queue->enqueue(del_token, dst_my_key);
                        }
                        pkt_processor_t::flow_hash_map[dst_crc].erase(dst_key);
                        if(flow_data->recv_pkt) {
                            rte_free(flow_data->recv_pkt);
                        }
                        rte_free(flow_data);
                        continue;
                    }
                    if(tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG) {
                        status = reply_rst_pkt(recv_pkts[i], send_pkts[send_size]);
                        if(status != status_t::OK) {
                            std::cout << "Failed to reply RST pkt.\n" << std::endl;
                            return status;
                        }
                        ++send_size;
                        tcp_hdr->tcp_flags = RTE_TCP_RST_FLAG;
                        status = forward_outbound_pkt(recv_pkts[i], send_pkts[send_size]);
                        if(status != status_t::OK) {
                            std::cout << "Failed to forward outbound pkt.\n" << std::endl;
                            return status;
                        }
                        ++send_size;
                        if(flow_data->state == OFFLOAD) {
                            pkt_processor_t::del_queue->enqueue(del_token, dst_my_key);
                        }
                        pkt_processor_t::flow_hash_map[dst_crc].erase(dst_key);
                        if(flow_data->recv_pkt) {
                            rte_free(flow_data->recv_pkt);
                        }
                        rte_free(flow_data);
                        continue;
                    }
                    #ifdef DEBUG
                    if(flow_data->state == OFFLOAD) {
                        std::cout << "[ERROR]: Receive an outbound packet in OFFLOAD state.\n";
                    }
                    #endif
                    status = forward_outbound_pkt(recv_pkts[i], send_pkts[send_size]);
                    if(status != status_t::OK) {
                        printf("[ERROR]: Forward outbound packet failed.\n");
                        return status;
                    }
                    ++send_size;
                    continue;
                }
                // default: {
                //     #ifdef DEBUG
                //     std::cout << "[ERROR]: Receive a packet with invalid state " << flow_data->state << std::endl;
                //     #endif
                //     continue;
                // }
            }
        }
        // #ifdef DEBUG
        // std::cout << "No flow data found" << std::endl;
        // #endif
        my_pair_t new_pair;
        new_pair.key = src_my_key;
        char *payload = (char*)((void*)tcp_hdr + (tcp_hdr->data_off >> 4) * 4);
        if(!payload_flag) {
            #ifdef DEBUG
            printf("[ERROR]: Receive a packet without payload.\n");
            #endif
            continue;
        }
        int size = 0;
        char *url = parse_payload(payload, ntohs(ip_hdr->total_length) - header_size, size);
        if(size == -1) {
            #ifdef DEBUG
            printf("[ERROR]: Receive a packet without url.\n");
            #endif
            continue;
        }
        
        rte_memcpy(url_copy, url, size);
        url_copy[size] = '\0';
        // #ifdef DEBUG
        // printf("[INFO]: Receive a packet with url: %s\n", url_copy);
        // #endif
        my_data_t *new_data = nullptr;
        if((new_data = pkt_processor_t::rule_controller->lookup_balancing_rule(url_copy)) != nullptr) {
            if(send_syn_pkt(new_data->d_index, recv_pkts[i], send_pkts[send_size]) != OK) {
                printf("[ERROR]: Send SYN packet failed.\n");
                status = status_t::INTERNAL_ERROR;
                return status;
            }
            flow_data = (flow_data_t *)rte_malloc_socket("flow_data", sizeof(flow_data_t), 0, 3);
            flow_data->state = BACKEND_SYN;
            flow_data->entry_data = *new_data;
            flow_data->recv_pkt = (char*)rte_malloc_socket("recv_pkt", recv_pkts[i]->data_len, 0, 3);
            memcpy(flow_data->recv_pkt, (void*)eth_hdr, recv_pkts[i]->data_len);
            flow_data->pkt_size = recv_pkts[i]->data_len;
            pkt_processor_t::flow_hash_map[src_crc].insert(src_key, flow_data);
            ++send_size;
            
        }
        #ifdef DEBUG
        else {
            printf("[ERROR]: No balancing rule found.\n");
        }
        #endif
        continue;
    }
    if(rte_eth_tx_burst(pkt_processor_t::port_id, queue_id, send_pkts, send_size) != send_size) {
        printf("[ERROR]: Transmit packets failed.\n");
        status = status_t::INTERNAL_ERROR;
    }
    // #ifdef DEBUG
    // std::cout << send_size << " packets sent" << std::endl;
    // #endif
    rte_pktmbuf_free_bulk(send_pkts + send_size, 2 * pkt_num - send_size);
    return status;
}

status_t pkt_processor_t::forward_inbound_pkt(uint8_t d_index, rte_mbuf* recv_buf, rte_mbuf *send_buf) {
    void *packet = rte_pktmbuf_mtod(recv_buf, void*);
    rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(send_buf, rte_ether_hdr*);
    memcpy(eth_hdr, packet, recv_buf->data_len);
    rte_ipv4_hdr *ip_hdr = (rte_ipv4_hdr*)(eth_hdr + 1);
    rte_tcp_hdr *tcp_hdr = (rte_tcp_hdr*)(ip_hdr + 1);
    
    server_info_t *server_info = pkt_processor_t::rule_controller->lookup_backend_server_info(d_index);
    if(server_info == nullptr) {
        printf("[ERROR]: Cannot find the backend server.\n");
        return status_t::INTERNAL_ERROR;
    }
    eth_hdr->s_addr.addr_bytes[0] = 0x0c;
    eth_hdr->s_addr.addr_bytes[1] = 0x42;
    eth_hdr->s_addr.addr_bytes[2] = 0xa1;
    eth_hdr->s_addr.addr_bytes[3] = 0xd1;
    eth_hdr->s_addr.addr_bytes[4] = 0xd0;
    eth_hdr->s_addr.addr_bytes[5] = 0xc8;
    rte_ether_addr_copy(&server_info->mac, &eth_hdr->d_addr);
    ip_hdr->dst_addr = htonl(server_info->ip);
    ip_hdr->hdr_checksum = 0;
    tcp_hdr->dst_port = htons(server_info->port);
    tcp_hdr->cksum = 0;
    send_buf->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
    send_buf->l2_len = sizeof(rte_ether_hdr);
    send_buf->l3_len = 20;
    send_buf->l4_len = (tcp_hdr->data_off >> 4) * 4;
    send_buf->data_len = ntohs(ip_hdr->total_length) + sizeof(rte_ether_hdr);
    send_buf->pkt_len = send_buf->data_len;
    return OK;
}

status_t pkt_processor_t::forward_outbound_pkt(rte_mbuf *recv_buf, rte_mbuf *send_buf) {
    void *packet = rte_pktmbuf_mtod(recv_buf, void*);
    rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(send_buf, rte_ether_hdr*);
    memcpy(eth_hdr, packet, recv_buf->data_len);
    rte_ipv4_hdr *ip_hdr = (rte_ipv4_hdr*)(eth_hdr + 1);
    rte_tcp_hdr *tcp_hdr = (rte_tcp_hdr*)(ip_hdr + 1);
    
    server_info_t *server_info = pkt_processor_t::rule_controller->get_virtual_server_info();
    if(server_info == nullptr) {
        //printf("[ERROR]: Cannot find the backend server.\n");
        return status_t::INTERNAL_ERROR;
    }
    eth_hdr->s_addr.addr_bytes[0] = 0x0c;
    eth_hdr->s_addr.addr_bytes[1] = 0x42;
    eth_hdr->s_addr.addr_bytes[2] = 0xa1;
    eth_hdr->s_addr.addr_bytes[3] = 0xd1;
    eth_hdr->s_addr.addr_bytes[4] = 0xd0;
    eth_hdr->s_addr.addr_bytes[5] = 0xc8;
    rte_ether_addr_copy(&server_info->mac, &eth_hdr->d_addr);
    ip_hdr->src_addr = htonl(server_info->ip);
    ip_hdr->hdr_checksum = 0;
    tcp_hdr->src_port = htons(server_info->port);
    tcp_hdr->cksum = 0;
    send_buf->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
    send_buf->l2_len = sizeof(rte_ether_hdr);
    send_buf->l3_len = 20;
    send_buf->l4_len = (tcp_hdr->data_off >> 4) * 4;
    send_buf->data_len = ntohs(ip_hdr->total_length) + sizeof(rte_ether_hdr);
    send_buf->pkt_len = send_buf->data_len;
    return OK;
}

status_t pkt_processor_t::reply_rst_pkt(rte_mbuf *recv_buf, rte_mbuf *send_buf) {
    void *packet = rte_pktmbuf_mtod(recv_buf, void*);
    rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(send_buf, rte_ether_hdr*);
    memcpy(eth_hdr, packet, 40 + sizeof(rte_ether_hdr));
    rte_ipv4_hdr *ip_hdr = (rte_ipv4_hdr*)(eth_hdr + 1);
    rte_tcp_hdr *tcp_hdr = (rte_tcp_hdr*)(ip_hdr + 1);
    //rte_ether_addr tmp;
    //rte_ether_addr_copy(&eth_hdr->d_addr, &tmp);
    rte_ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
    //rte_ether_addr_copy(&tmp, &eth_hdr->s_addr);
    eth_hdr->s_addr.addr_bytes[0] = 0x0c;
    eth_hdr->s_addr.addr_bytes[1] = 0x42;
    eth_hdr->s_addr.addr_bytes[2] = 0xa1;
    eth_hdr->s_addr.addr_bytes[3] = 0xd1;
    eth_hdr->s_addr.addr_bytes[4] = 0xd0;
    eth_hdr->s_addr.addr_bytes[5] = 0xc8;
    uint32_t tmp_ip = ip_hdr->src_addr;
    ip_hdr->src_addr = ip_hdr->dst_addr;
    ip_hdr->dst_addr = tmp_ip;
    ip_hdr->hdr_checksum = 0;
    ip_hdr->version_ihl = 5 + (ip_hdr->version_ihl & 0xf0);
    ip_hdr->total_length = htons(40);
    uint16_t tmp_port = tcp_hdr->src_port;
    tcp_hdr->src_port = tcp_hdr->dst_port;
    tcp_hdr->dst_port = tmp_port;
    uint32_t seq_num = ntohl(tcp_hdr->sent_seq);
    uint32_t ack_num = ntohl(tcp_hdr->recv_ack);
    tcp_hdr->recv_ack = htonl(seq_num + recv_buf->data_len - recv_buf->l2_len - recv_buf->l3_len - recv_buf->l4_len);
    tcp_hdr->sent_seq = htonl(ack_num);
    tcp_hdr->data_off = 5 << 4;
    tcp_hdr->tcp_flags = RTE_TCP_RST_FLAG;
    tcp_hdr->cksum = 0;
    send_buf->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
    send_buf->l2_len = sizeof(rte_ether_hdr);
    send_buf->l3_len = 20;
    send_buf->l4_len = 20;
    send_buf->data_len = ntohs(ip_hdr->total_length) + sizeof(rte_ether_hdr);
    send_buf->pkt_len = send_buf->data_len;
    return OK;
}

status_t pkt_processor_t::send_rst_pkt(uint8_t d_index, rte_mbuf *recv_buf, rte_mbuf *send_buf) {
    void *packet = rte_pktmbuf_mtod(recv_buf, void*);
    rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(send_buf, rte_ether_hdr*);
    memcpy(eth_hdr, packet, 40 + sizeof(rte_ether_hdr));
    rte_ipv4_hdr *ip_hdr = (rte_ipv4_hdr*)(eth_hdr + 1);
    rte_tcp_hdr *tcp_hdr = (rte_tcp_hdr*)(ip_hdr + 1);
    server_info_t *server_info = pkt_processor_t::rule_controller->lookup_backend_server_info(d_index);
    rte_ether_addr_copy(&server_info->mac, &eth_hdr->d_addr);
    eth_hdr->s_addr.addr_bytes[0] = 0x0c;
    eth_hdr->s_addr.addr_bytes[1] = 0x42;
    eth_hdr->s_addr.addr_bytes[2] = 0xa1;
    eth_hdr->s_addr.addr_bytes[3] = 0xd1;
    eth_hdr->s_addr.addr_bytes[4] = 0xd0;
    eth_hdr->s_addr.addr_bytes[5] = 0xc8;
    ip_hdr->dst_addr = server_info->ip;
    ip_hdr->version_ihl = 5 + (ip_hdr->version_ihl & 0xf0);
    ip_hdr->total_length = htons(40);  
    ip_hdr->hdr_checksum = 0;
    tcp_hdr->dst_port = server_info->port;
    tcp_hdr->tcp_flags = RTE_TCP_RST_FLAG;
    tcp_hdr->data_off = 5 << 4;
    tcp_hdr->cksum = 0;
    send_buf->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
    send_buf->l2_len = sizeof(rte_ether_hdr);
    send_buf->l3_len = 20;
    send_buf->l4_len = 20;
    send_buf->data_len = 40 + sizeof(rte_ether_hdr);
    send_buf->pkt_len = send_buf->data_len;
    return OK; 
}

status_t pkt_processor_t::send_cached_pkt(uint8_t d_index, char *cached_pkt, rte_mbuf *send_buf, size_t size) {
    rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(send_buf, rte_ether_hdr*);
    memcpy(eth_hdr, cached_pkt, size);
    server_info_t *server_info = pkt_processor_t::rule_controller->lookup_backend_server_info(d_index);
    rte_ether_addr_copy(&server_info->mac, &eth_hdr->d_addr);
    eth_hdr->s_addr.addr_bytes[0] = 0x0c;
    eth_hdr->s_addr.addr_bytes[1] = 0x42;
    eth_hdr->s_addr.addr_bytes[2] = 0xa1;
    eth_hdr->s_addr.addr_bytes[3] = 0xd1;
    eth_hdr->s_addr.addr_bytes[4] = 0xd0;
    eth_hdr->s_addr.addr_bytes[5] = 0xc8;
    rte_ipv4_hdr *ip_hdr = (rte_ipv4_hdr*)(eth_hdr + 1);
    ip_hdr->dst_addr = htonl(server_info->ip);
    ip_hdr->hdr_checksum = 0;
    rte_tcp_hdr *tcp_hdr = (rte_tcp_hdr*)(ip_hdr + 1);
    tcp_hdr->dst_port = htons(server_info->port);
    tcp_hdr->cksum = 0;
    send_buf->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
    send_buf->l2_len = sizeof(rte_ether_hdr);
    send_buf->l3_len = 20;
    send_buf->l4_len = (tcp_hdr->data_off >> 4) * 4;
    send_buf->data_len = ntohs(ip_hdr->total_length) + sizeof(rte_ether_hdr);
    send_buf->pkt_len = send_buf->data_len;
    return OK;
}

status_t pkt_processor_t::send_syn_pkt(uint8_t d_index, rte_mbuf *recv_buf, rte_mbuf *send_buf) {
    void *packet = rte_pktmbuf_mtod(recv_buf, void*);
    rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(send_buf, rte_ether_hdr*);
    memcpy(eth_hdr, packet, 52 + sizeof(rte_ether_hdr));
    server_info_t *server_info = pkt_processor_t::rule_controller->lookup_backend_server_info(d_index);

    rte_ether_addr_copy(&server_info->mac, &eth_hdr->d_addr);
    rte_ipv4_hdr *ip_hdr = (rte_ipv4_hdr*)(eth_hdr + 1);
    ip_hdr->dst_addr = htonl(server_info->ip);
    ip_hdr->version_ihl = 5 + (ip_hdr->version_ihl & 0xf0);
    ip_hdr->total_length = htons(52);
    ip_hdr->hdr_checksum = 0;
    rte_tcp_hdr *tcp_hdr = (rte_tcp_hdr*)(ip_hdr + 1);
    tcp_hdr->dst_port = htons(server_info->port);
    tcp_hdr->tcp_flags = RTE_TCP_SYN_FLAG;
    tcp_hdr->data_off = 8 << 4;
    tcp_hdr->sent_seq = htonl(ntohl(tcp_hdr->sent_seq) - 1);
    tcp_hdr->recv_ack = htonl(ntohl(tcp_hdr->recv_ack) - 1);
    tcp_hdr->cksum = 0;
    void *option = (void *)(tcp_hdr + 1);
    memcpy(option, option_char, sizeof(option_char));
    send_buf->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
    send_buf->l2_len = sizeof(rte_ether_hdr);
    send_buf->l3_len = 20;
    send_buf->l4_len = 32;
    send_buf->data_len = ntohs(ip_hdr->total_length) + sizeof(rte_ether_hdr);
    send_buf->pkt_len = send_buf->data_len;
    return OK;
}

int pkt_processor_t::worker_fun(void *args) {
    std::cout << "Worker thread is running." << std::endl;
    int queue_id = this->queue_id;
    rte_mbuf *recv_pkts[pkt_processor_t::dpdk_config->burst_size];
    while(!exit_flag) {
        int pkt_num = rte_eth_rx_burst(pkt_processor_t::port_id, queue_id, recv_pkts, pkt_processor_t::dpdk_config->burst_size);
        if(pkt_num == 0) {
            continue;
        }
        status = process_pkts(recv_pkts, pkt_num);
        if(status != OK) {
            printf("[ERROR]: Process packets failed.\n");
        }
        rte_pktmbuf_free_bulk(recv_pkts, pkt_num);
    }
    return 0;
}

status_t pkt_processor_t::init_static_variable(int argc, char **argv, dpdk_config_t *dpdk_config,
                                               rule_controller_t *rule_controller, 
                                               moodycamel::ConcurrentQueue<my_pair_t> *add_queue,
                                               moodycamel::ConcurrentQueue<my_key_t> *del_queue,
                                               libcuckoo::cuckoohash_map<uint64_t, flow_data_t *> *flow_hash_map) {
    pkt_processor_t::add_queue = add_queue;
    pkt_processor_t::del_queue = del_queue;
    pkt_processor_t::flow_hash_map = flow_hash_map;
    for (int i = 0; i < 256; i++) {
        uint8_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x80) {
                crc = (crc << 1) ^ 0x07; // 使用多项式0x07
            } else {
                crc = crc << 1;
            }
        }
        crc8_table[i] = crc;
    }
    pkt_processor_t::rule_controller = rule_controller;
    pkt_processor_t::dpdk_config = dpdk_config;
    int ret = rte_eal_init(argc, argv);
    if(ret < 0) {
        perror("rte_eal_init");
        return INTERNAL_ERROR;
    }
    pkt_processor_t::mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", dpdk_config->num_mbufs, dpdk_config->mbuf_cache_size, 0, dpdk_config->mbuf_data_room_size, rte_socket_id());
    if(pkt_processor_t::mbuf_pool == nullptr) {
        perror("rte_pktmbuf_pool_create");
        return INTERNAL_ERROR;
    }
    ret = rte_eth_dev_get_port_by_name(dpdk_config->pci_addr, &pkt_processor_t::port_id);
    if(ret < 0) {
        perror("rte_eth_dev_get_port_by_name");
        return INTERNAL_ERROR;
    }
    rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.offloads = DEV_RX_OFFLOAD_CHECKSUM;
    port_conf.txmode.offloads = DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM;
    port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
    port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP| ETH_RSS_TCP;
    ret = rte_eth_dev_configure(pkt_processor_t::port_id, dpdk_config->queue_size, dpdk_config->queue_size, &port_conf);
    if(ret < 0) {
        perror("rte_eth_dev_configure");
        return INTERNAL_ERROR;
    }
    rte_eth_dev_info dev_info;
    ret = rte_eth_dev_info_get(pkt_processor_t::port_id, &dev_info);
    if(ret < 0) {
        perror("rte_eth_dev_info_get");
        return INTERNAL_ERROR;
    }
    rte_eth_rxconf rxconf = dev_info.default_rxconf;
    rte_eth_txconf txconf = dev_info.default_txconf;
    txconf.offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;
    txconf.offloads |= DEV_TX_OFFLOAD_TCP_CKSUM;
    for(int i = 0; i < dpdk_config->queue_size; ++i) {
        ret = rte_eth_rx_queue_setup(pkt_processor_t::port_id, i, 2048, rte_socket_id(), &rxconf, mbuf_pool);
        if(ret < 0)
        {
            perror("rte_eth_rx_queue_setup");
            return INTERNAL_ERROR;
        }

        ret = rte_eth_tx_queue_setup(pkt_processor_t::port_id, i, 2048, rte_socket_id(), &txconf);
        if(ret < 0) 
        {
            perror("rte_eth_tx_queue_setup");
            return INTERNAL_ERROR;
        }
    }
    ret = rte_eth_promiscuous_enable(pkt_processor_t::port_id);
    if(ret < 0) {
        perror("rte_eth_promiscuous_enable");
        return INTERNAL_ERROR;
    }
    ret = rte_eth_dev_start(pkt_processor_t::port_id);
    if(ret < 0) {
        perror("rte_eth_dev_start");
        return INTERNAL_ERROR;
    }
    std::cout << "Initialization is successful." << std::endl;
    return OK;
}

int pkt_processor_t::worker_run_warpper(void *args) {
    pkt_processor_t *pkt_processor = (pkt_processor_t*)args;
    pkt_processor->worker_fun(nullptr);
    return 0;
}

void pkt_processor_t::run(int core_id) {
    exit_flag = false;
    rte_eal_remote_launch(&pkt_processor_t::worker_run_warpper, this, core_id);
}

void pkt_processor_t::stop() {
    exit_flag = true;
    uint32_t core_id;
    RTE_LCORE_FOREACH_SLAVE(core_id) {
        rte_eal_wait_lcore(core_id);
    }
}

void pkt_processor_t::destroy_static_variable() {
    // 清理哈希表中的条目
    for(int i = 0; i < 256; ++i) {
        for(auto it = pkt_processor_t::flow_hash_map[i].lock_table().begin(); it != pkt_processor_t::flow_hash_map[i].lock_table().end(); it++) {
            flow_data_t *flow_data = it->second;
            if(flow_data->recv_pkt != nullptr) {
                rte_free(flow_data->recv_pkt);
            }
            rte_free(flow_data);
        }
        pkt_processor_t::flow_hash_map[i].clear();
    }

    // 释放内存池
    rte_mempool_free(pkt_processor_t::mbuf_pool);

    // 停止并关闭所有队列
    rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(pkt_processor_t::port_id, &dev_info);
    uint16_t nb_rx_queues = dev_info.nb_rx_queues;
    uint16_t nb_tx_queues = dev_info.nb_tx_queues;

    for (uint16_t q = 0; q < nb_rx_queues; q++) {
        rte_eth_dev_rx_queue_stop(pkt_processor_t::port_id, q);
    }

    for (uint16_t q = 0; q < nb_tx_queues; q++) {
        rte_eth_dev_tx_queue_stop(pkt_processor_t::port_id, q);
    }

    // 停止并关闭端口
    rte_eth_dev_stop(pkt_processor_t::port_id);
    rte_eth_dev_close(pkt_processor_t::port_id);

    // 关闭 EAL
    rte_eal_cleanup();
}