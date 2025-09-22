#include "controller_client.h"

static auto logger = spdlog::stdout_color_mt("controller_client");

void ControllerClient::_update_info() 
{
    size_t recv_size = 0;
    if (_connector->recv_message(_recv_buffer, ETH_FRAME_LEN, recv_size) != MiresgaStatus_t::OK) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to receive message from Tofino");
        throw std::runtime_error("Failed to receive message");
    }
    if (recv_size == 0) {
        SPDLOG_LOGGER_ERROR(logger, "Connection with Tofino has been closed");
        throw std::runtime_error("Connection closed");
    }
    OperationType_t op_type = static_cast<OperationType_t>(_recv_buffer[0]);
    switch(op_type) {
        case OperationType_t::INIT_RDMA_ENGINE: {
            SPDLOG_LOGGER_DEBUG(logger, "Receive INIT_RDMA_ENGINE from Tofino");
            uint8_t num_add = _recv_buffer[1];
            SPDLOG_LOGGER_DEBUG(logger, "Number of new RDMA engines: {}", num_add);
            size_t now_bytes = 2;
            std::string msg;
            msg.append(1, static_cast<char>(OperationType_t::UPDATE_RDMA_INFO));
            msg.append(1, static_cast<char>(num_add));
            for (uint8_t i = 0; i < num_add; ++i) {
                uint8_t remote_id = _recv_buffer[now_bytes];
                now_bytes++;
                msg.append(_rdma_manager->add_engine(remote_id));
            }
            _connector->send_message(msg.data(), msg.size());
            SPDLOG_LOGGER_DEBUG(logger, "Sent RDMA infos to Tofino");
            break;
        }
        case OperationType_t::UPDATE_RDMA_INFO: {
            SPDLOG_LOGGER_DEBUG(logger, "Receive UPDATE_RDMA_INFO from Tofino");
            uint8_t num_update = _recv_buffer[1];
            SPDLOG_LOGGER_DEBUG(logger, "Number of RDMA engines to update: {}", num_update);
            size_t now_bytes = 2;
            for (uint8_t i = 0; i < num_update; ++i) {
                uint8_t remote_id = _recv_buffer[now_bytes];
                now_bytes++;
                uint8_t num_crcs = _recv_buffer[now_bytes];
                now_bytes++;
                std::vector<uint8_t> crcs(_recv_buffer + now_bytes, _recv_buffer + now_bytes + num_crcs);
                now_bytes += num_crcs;
                RDMAInfo_t* remote_rdma_info = new RDMAInfo_t;
                memcpy(remote_rdma_info, _recv_buffer + now_bytes, sizeof(RDMAInfo_t));
                now_bytes += sizeof(RDMAInfo_t);
                SPDLOG_LOGGER_DEBUG(logger, "Updating RDMA engine {}, num_crcs {}", remote_id, num_crcs);
                SPDLOG_LOGGER_DEBUG(logger, "crcs:{}", fmt::join(crcs, ","));
                _rdma_manager->update_engine(remote_id, remote_rdma_info, crcs);
            }
            std::string complete_msg = "";
            complete_msg.append(1, static_cast<char>(OperationType_t::COMPLETE));
            _connector->send_message(complete_msg.data(), complete_msg.size());
            break;
        }
        case OperationType_t::RDMA_START: {
            uint8_t num_start = _recv_buffer[1];
            SPDLOG_LOGGER_INFO(logger, "Number of RDMA engines to start: {}", num_start);
            SPDLOG_LOGGER_DEBUG(logger, "Starting RDMA engines ID: {}", fmt::join(std::vector<uint8_t>(_recv_buffer + 2, _recv_buffer + 2 + num_start), ","));
            size_t now_bytes = 2;
            for (uint8_t i = 0; i < num_start; ++i) {
                uint8_t remote_id = _recv_buffer[now_bytes];
                now_bytes++;
                _rdma_manager->start_engine(remote_id);
            }
            break;
        }
        case OperationType_t::RDMA_STOP: {
            uint8_t remote_id = _recv_buffer[1];
            SPDLOG_LOGGER_WARN(logger, "RDMA engine {} reports error and will be removed", remote_id);
            uint8_t num_update_id = _recv_buffer[2];
            SPDLOG_LOGGER_DEBUG(logger, "Number of IDs to update: {}", num_update_id);
            size_t now_bytes = 3;
            std::unordered_map<uint8_t, uint8_t> crc_2_id;
            for (uint8_t i = 0; i < num_update_id; ++i) {
                uint8_t update_id = _recv_buffer[now_bytes];
                now_bytes++;
                uint8_t num_crcs = _recv_buffer[now_bytes];
                SPDLOG_LOGGER_DEBUG(logger, "Updating ID {} for {} CRCs", update_id, num_crcs);
                SPDLOG_LOGGER_DEBUG(logger, "CRCs: {}", fmt::join(std::vector<uint8_t>(_recv_buffer + now_bytes + 1, _recv_buffer + now_bytes + 1 + num_crcs), ","));
                now_bytes++;
                for (uint8_t j = 0; j < num_crcs; ++j) {
                    uint8_t crc = _recv_buffer[now_bytes];
                    now_bytes++;
                    crc_2_id[crc] = update_id;
                }
            }
            _rdma_manager->remove_engine(remote_id, crc_2_id);
            break;
        }
        case OperationType_t::UPDATE_RULE: {
            SPDLOG_LOGGER_INFO(logger, "Receive UPDATE_RULE from Tofino");
            uint8_t add_size = _recv_buffer[1];
            SPDLOG_LOGGER_DEBUG(logger, "Number of rules to add: {}", add_size);
            uint8_t del_size = _recv_buffer[2];
            SPDLOG_LOGGER_DEBUG(logger, "Number of rules to delete: {}", del_size);
            size_t offset = 3;
            for (uint8_t i = 0; i < add_size; ++i) {
                char* host_name = _recv_buffer + offset;
                offset += strlen(host_name) + 1;
                RuleEntry_t* rule = new RuleEntry_t;
                rule->d_index = _recv_buffer[offset];
                offset++;
                rule->offload_flag = _recv_buffer[offset];
                offset++;
                _rule_manager->add_rule(host_name, rule);
            }
            for (uint8_t i = 0; i < del_size; ++i) {
                char* host_name = _recv_buffer + offset;
                offset += strlen(host_name) + 1;
                _rule_manager->remove_rule(host_name);
            }
            break;
        }
        case UPDATE_D_INDEX: {
            SPDLOG_LOGGER_INFO(logger, "Receive UPDATE_D_INDEX from Tofino");
            uint8_t add_size = _recv_buffer[1];
            SPDLOG_LOGGER_DEBUG(logger, "Number of backend server infos to add: {}", add_size);
            uint8_t del_size = _recv_buffer[2];
            SPDLOG_LOGGER_DEBUG(logger, "Number of backend server infos to delete: {}", del_size);
            size_t offset = 3;
            for (uint8_t i = 0; i < add_size; ++i)
            {
                uint8_t d_index = _recv_buffer[offset];
                offset++;
                ServerInfo_t* server_info = new ServerInfo_t;
                memcpy(server_info, _recv_buffer + offset, sizeof(ServerInfo_t));
                offset += sizeof(ServerInfo_t);
                _rule_manager->add_backend_server_info(d_index, server_info);
            }
            for (uint8_t i = 0; i < del_size; ++i)
            {
                uint8_t d_index = _recv_buffer[offset];
                offset++;
                _rule_manager->remove_backend_server_info(d_index);
            }
            break;
        }
        case UPDATE_V_INFO: {
            SPDLOG_LOGGER_INFO(logger, "Receive UPDATE_V_INFO from Tofino");
            ServerInfo_t *server_info = reinterpret_cast<ServerInfo_t*>(_recv_buffer + 1);
            _rule_manager->set_virtual_server_info(server_info);

            break;
        }
        case SYNC_OLD_DATA: {
            SPDLOG_LOGGER_INFO(logger, "Receive SYNC_OLD_DATA from Tofino");
            uint8_t remote_id = _recv_buffer[1];
            SPDLOG_LOGGER_DEBUG(logger, "Remote RDMA ID: {}", remote_id);
            uint8_t num_crcs = _recv_buffer[2];
            SPDLOG_LOGGER_DEBUG(logger, "Number of CRCs to sync: {}", num_crcs);
            SPDLOG_LOGGER_DEBUG(logger, "CRCs to sync: {}", fmt::join(std::vector<uint8_t>(_recv_buffer + 3, _recv_buffer + 3 + num_crcs), ","));
            size_t now_bytes = 3;
            for (uint8_t i = 0; i < num_crcs; ++i) {
                uint8_t crc = _recv_buffer[now_bytes];
                now_bytes++;
                std::vector<MiresgaOFTEntry_t> crc_entries = _flow_table->get_crc_entries(crc);
                _rdma_manager->add_old_flow_data(remote_id, crc_entries);
            }

        }
        case OK: {
            break;
        }
        default:
            throw std::runtime_error("Unknown operation type");
    }

}

void ControllerClient::_main_loop()
{
    SPDLOG_LOGGER_INFO(logger, "ControllerClient main loop started");
    while (!_exit_flag) {
        epoll_event events[10];
        int nfds = epoll_wait(_epoll_fd, events, 10, -1);
        for (int i = 0; i < nfds; ++i) {
            if (events[i].data.fd == _connector->socket) {
                _update_info();
            }
            else if(events[i].data.fd == _offload_timerfd) {
                SPDLOG_LOGGER_DEBUG(logger, "Offload timer triggered");
                uint64_t expirations;
                ssize_t recv_size = read(_offload_timerfd, &expirations, sizeof(expirations));
                if (recv_size == -1) {
                    throw std::runtime_error("Failed to read offload timerfd");
                }
                ssize_t send_size = _entry_manager->serialize_msg(_send_buffer);
                if (send_size == -1) {
                    throw std::runtime_error("Failed to serialize offload message");
                }
                if (send_size > 0) {
                    if (_connector->send_message(_send_buffer, send_size) != MiresgaStatus_t::OK) {
                        throw std::runtime_error("Failed to send offload message");
                    }
                }
            }
            else if(events[i].data.fd == _sync_timerfd) {
                SPDLOG_LOGGER_DEBUG(logger, "Sync timer triggered");
                uint64_t expirations;
                ssize_t recv_size = read(_sync_timerfd, &expirations, sizeof(expirations));
                if (recv_size == -1) {
                    throw std::runtime_error("Failed to read sync timerfd");
                }
                _rdma_manager->sync_states();
            }
            else if(events[i].data.u32 == CQ_PRESENTER) {
                SPDLOG_LOGGER_DEBUG(logger, "Processing RDMA completions");
                std::vector<ibv_wc> completions = _rdma_manager->process_cqe();
                for (const auto& wc : completions) {
                    uint64_t remote_id = wc.wr_id;
                    if (wc.status != IBV_WC_SUCCESS) {
                        SPDLOG_LOGGER_ERROR(logger, "RDMA operation failed for engine {}: {}", remote_id, ibv_wc_status_str(wc.status));
                        // Notify Tofino to stop using this RDMA engine
                        char error_msg[2];
                        error_msg[0] = static_cast<char>(OperationType_t::RDMA_STOP);
                        error_msg[1] = static_cast<char>(remote_id);
                        if (_connector->send_message(error_msg, sizeof(error_msg)) != MiresgaStatus_t::OK) {
                            throw std::runtime_error("Failed to send RDMA_STOP message");
                        }
                    } else if (wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
                        SPDLOG_LOGGER_DEBUG(logger, "Received RDMA with immediate from engine {}", remote_id);
                        uint32_t imm_data = wc.imm_data;
                        void* recv_buffer = _rdma_manager->get_recv_addr(remote_id);
                        uint16_t add_entry = static_cast<uint16_t>(imm_data >> 16);
                        SPDLOG_LOGGER_DEBUG(logger, "Number of entries to add: {}", add_entry);
                        uint16_t del_key = static_cast<uint16_t>(imm_data & 0xFFFF);
                        SPDLOG_LOGGER_DEBUG(logger, "Number of keys to delete: {}", del_key);
                        size_t offset = 0;
                        if (add_entry > 0) {
                           for (uint16_t i = 0; i < add_entry; ++i) {
                                MiresgaOFTEntry_t* entry = reinterpret_cast<MiresgaOFTEntry_t*>(
                                                               reinterpret_cast<uint8_t*>(recv_buffer) + offset
                                                         );
                                offset += sizeof(MiresgaOFTEntry_t);
                                MiresgaFlowData_t* data = new MiresgaFlowData_t();
                                data->entry_data = *entry;
                                data->state = static_cast<FlowState_t>(entry->data.flow_state);
                                _flow_table->remove_flow(data->entry_data.key);
                                _flow_table->insert_flow(data->entry_data.key, data);
                            }
                        }
                        if (del_key > 0) {
                            for (uint16_t i = 0; i < del_key; ++i) {
                                MiresgaOFTKey_t* key = reinterpret_cast<MiresgaOFTKey_t*>(
                                    reinterpret_cast<uint8_t*>(recv_buffer) + offset);
                                offset += sizeof(MiresgaOFTKey_t);
                                _flow_table->remove_flow(*key);
                            }
                        }
                    }
                    else if (wc.opcode == IBV_WC_RDMA_WRITE) {
                        SPDLOG_LOGGER_DEBUG(logger, "RDMA write completed for engine {}", remote_id);
                        _rdma_manager->sync_complete(remote_id);
                    }
                    else {
                        SPDLOG_LOGGER_WARN(logger, "Unknown completion opcode {} for engine {}", 
                                           static_cast<int>(wc.opcode), remote_id);
                    }
                }
            }
        }
    }
    SPDLOG_LOGGER_WARN(logger, "ControllerClient main loop exited");
}

ControllerClient::ControllerClient(char* switch_ip, uint16_t switch_port, 
                                   char* rdma_dev_name)
{
    SPDLOG_LOGGER_INFO(logger, "Initializing ControllerClient");
    _epoll_fd = epoll_create1(0);
    _exit_flag = false;
    if (_epoll_fd == -1) {
        throw std::runtime_error("Failed to create epoll file descriptor");
    }
    SPDLOG_LOGGER_DEBUG(logger, "epoll started");
    try {
        _connector = new ControllerConnector(switch_ip, switch_port);
        SPDLOG_LOGGER_DEBUG(logger, "Client Connector started");
        _entry_manager = EntryManager::get_instance();
        SPDLOG_LOGGER_DEBUG(logger, "Entry Manager started");
        _rule_manager = RuleManager::get_instance();
        SPDLOG_LOGGER_DEBUG(logger, "Rule Manager started");
    }
    catch (const std::exception& e) {
        throw std::runtime_error("Failed to initialize ControllerClient: " + std::string(e.what()));
    }

    epoll_event sock_ev;
    sock_ev.events = EPOLLIN;
    sock_ev.data.fd = _connector->socket;
    if (epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, _connector->socket, &sock_ev) == -1) {
        throw std::runtime_error("Failed to add socket to epoll");
    }
    SPDLOG_LOGGER_DEBUG(logger, "Socket added to epoll");
    _flow_table = FlowTable::get_instance();
    SPDLOG_LOGGER_DEBUG(logger, "Flow Table created");
    RDMAManager::init_rdma_manager(rdma_dev_name, _epoll_fd);
    SPDLOG_LOGGER_DEBUG(logger, "RDMA Manager started");
    _rdma_manager = RDMAManager::get_instance();
    _offload_timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (_offload_timerfd == -1) {
        throw std::runtime_error("Failed to create offload timerfd");
    }

    struct itimerspec offload_timer_value;
    offload_timer_value.it_value.tv_sec = 0;
    offload_timer_value.it_value.tv_nsec = 10000000;  // 0.01 seconds in nanoseconds
    offload_timer_value.it_interval.tv_sec = 0;
    offload_timer_value.it_interval.tv_nsec = 10000000;  // 0.01 seconds in nanoseconds

    if (timerfd_settime(_offload_timerfd, 0, &offload_timer_value, NULL) == -1) {
        throw std::runtime_error("Failed to set offload timer");
    }

    epoll_event offload_ev;
    offload_ev.events = EPOLLIN;
    offload_ev.data.fd = _offload_timerfd;
    if (epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, _offload_timerfd, &offload_ev) == -1) {
        throw std::runtime_error("Failed to add offload timerfd to epoll");
    }

    // Create and configure the sync timerfd
    _sync_timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (_sync_timerfd == -1) {
        throw std::runtime_error("Failed to create sync timerfd");
    }

    struct itimerspec sync_timer_value;
    sync_timer_value.it_value.tv_sec = 0;
    sync_timer_value.it_value.tv_nsec = 100000000;  // 0.1 seconds in nanoseconds
    sync_timer_value.it_interval.tv_sec = 0;
    sync_timer_value.it_interval.tv_nsec = 100000000;  // 0.1 seconds in nanoseconds

    if (timerfd_settime(_sync_timerfd, 0, &sync_timer_value, NULL) == -1) {
        throw std::runtime_error("Failed to set sync timer");
    }

    epoll_event sync_ev;
    sync_ev.events = EPOLLIN;
    sync_ev.data.fd = _sync_timerfd;
    if (epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, _sync_timerfd, &sync_ev) == -1) {
        throw std::runtime_error("Failed to add sync timerfd to epoll");
    }
    SPDLOG_LOGGER_DEBUG(logger, "Timers added to epoll");
    _client_thread = std::thread(&ControllerClient::_main_loop, this);
    _client_thread.detach();
}

ControllerClient::~ControllerClient()
{
    stop();
}

void ControllerClient::init_controller_client(char* switch_ip, uint16_t switch_port, 
                                              char* rdma_dev_name)
{
    if (_instance == nullptr) {
        _instance = new ControllerClient(switch_ip, switch_port, rdma_dev_name);
    }
}

ControllerClient* ControllerClient::get_instance()
{
    if (_instance == nullptr) {
        throw std::runtime_error("ControllerClient is not initialized");
    }
    return _instance;
}

void ControllerClient::destroy_instance()
{
    if (_instance != nullptr) {
        delete _instance;
        _instance = nullptr;
    }
}

void ControllerClient::stop()
{
    _exit_flag = true;
    if (_epoll_fd != -1) {
        close(_epoll_fd);
        _epoll_fd = -1;
    }
    if (_connector != nullptr) {
        delete _connector;
        _connector = nullptr;
    }
}