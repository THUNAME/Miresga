#include "controller.h"

void FrontendController_t::_remove_frontend(uint8_t id) {
    int fd = _id_2_socket_fd[id];
    if (epoll_ctl(_epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        throw std::runtime_error("Failed to remove connection from epoll");
    }
    close(fd);
    _socket_fd_2_id.erase(fd);
    _id_2_socket_fd.erase(id);
    _active_ids.erase(id);
    _idle_ids.insert(id);
    size_t num_crc = _id_2_crcs[id].size();
    size_t num_active_id = _active_ids.size();
    if (num_active_id == 0) {
        std::cout << "All frontends disconnected, reset to INIT state" << std::endl;
        _state = INIT;
        _client->start_updating({});
        _client->finish_updating();
    } else if(num_active_id > 1){
        auto sync_crcs = _id_2_sync_crcs[id];
        size_t num_if_erase_crcs = 256 / num_active_id;
        size_t extra = 256 % num_active_id;
        _id_2_sync_crcs.erase(id);
        for (auto& [other_id, crcs] : sync_crcs) {
            size_t num_add_crcs = crcs.size();
            _id_2_crcs[other_id].insert(_id_2_crcs[other_id].end(), crcs.begin(), crcs.end());
            uint8_t idx = 0;
            size_t offset = 0;
            std::string stop_msg;
            stop_msg.append(1, static_cast<char>(RDMA_STOP));
            stop_msg.append(1, static_cast<char>(id));
            stop_msg.append(1, static_cast<char>(0));
            size_t num_update = 0;
            for (auto& active_id : _active_ids) {
                if (active_id == other_id) {
                    break;
                }
                size_t target_size = num_if_erase_crcs;
                if (idx < extra) {
                    target_size++;
                }
                idx++;
                size_t need_add_size = target_size - _id_2_sync_crcs[other_id][active_id].size();
                if (need_add_size > 0) {
                    num_update++;
                    stop_msg.append(1, static_cast<char>(active_id));
                    stop_msg.append(1, static_cast<char>(need_add_size));
                    for (size_t i = 0; i < need_add_size; ++i) {
                        stop_msg.append(1, static_cast<char>(crcs[offset + i]));
                        _id_2_sync_crcs[other_id][active_id].push_back(crcs[offset + i]);
                    }
                    offset += need_add_size;
                }
            }
            stop_msg[2] = static_cast<char>(num_update);
            int other_fd = _id_2_socket_fd[other_id];
            if (send(other_fd, stop_msg.c_str(), stop_msg.size(), 0) < 0) {
                throw std::runtime_error("Failed to send rdma stop message");
            }
        }
        std::unordered_map<uint8_t, EgressPortEntry_t> crc_2_egressportentry;
        for (const auto& [other_id, crcs] : _id_2_crcs) {
            for (const auto& crc : crcs) {
                crc_2_egressportentry[crc] = _id_2_egress_port[other_id];
            }
        }
        _client->start_updating(crc_2_egressportentry);
        _client->finish_updating();
    }
    else {
        _id_2_sync_crcs.clear();
        std::string stop_msg;
        uint8_t last_id = *_active_ids.begin();
        std::unordered_map<uint8_t, EgressPortEntry_t> crc_2_egressportentry;
        _id_2_crcs[last_id].insert(_id_2_crcs[last_id].end(), 
                                   _id_2_crcs[id].begin(), 
                                   _id_2_crcs[id].end());
        for (auto& crc : _id_2_crcs[last_id]) {
            crc_2_egressportentry[crc] = _id_2_egress_port[last_id];
        }
        _client->start_updating(crc_2_egressportentry);
        _client->finish_updating();
        stop_msg.append(1, static_cast<char>(RDMA_STOP));
        stop_msg.append(1, static_cast<char>(id));
        stop_msg.append(1, static_cast<char>(0));
        if (send(_id_2_socket_fd[last_id], stop_msg.c_str(), stop_msg.size(), 0) < 0) {
            throw std::runtime_error("Failed to send rdma stop message");
        }
    }
    _id_2_crcs.erase(id);
    _id_2_need_changed_crcs.erase(id);
    _id_2_rdma_info.erase(id);
    _id_2_egress_port.erase(id);
}

void FrontendController_t::_update_rdma_info() {
    assert(_state == WAIT_RDMA_INFO);
    std::string add_msg;
    add_msg.append(1, static_cast<char>(UPDATE_RDMA_INFO));
    add_msg.append(1, static_cast<char>(_active_ids.size() - 1));
    for (auto id : _active_ids) {
        if (id == _updating_id) {
            continue;
        }
        add_msg.append(1, static_cast<char>(id));
        add_msg.append(1, static_cast<char>(_id_2_sync_crcs[_updating_id][id].size()));
        char* crc_ptr = reinterpret_cast<char*>(_id_2_sync_crcs[_updating_id][id].data());
        add_msg.append(crc_ptr, _id_2_sync_crcs[_updating_id][id].size());
        RDMAInfo_t rdma_info = _id_2_rdma_info[id][_updating_id];
        char* info_ptr = reinterpret_cast<char*>(&rdma_info);
        add_msg.append(info_ptr, sizeof(RDMAInfo_t));
    }
    int _updating_fd = _id_2_socket_fd[_updating_id];
    if (send(_updating_fd, add_msg.c_str(), add_msg.size(), 0) < 0) {
        throw std::runtime_error("Failed to send add rdma info message");
    }
    // Update other frontends.
    // Note: Actually, one for loop can handle all the sending tasks. We divide it into two 
    // for loops to make sure the added frontend can initialize all its RDMA connections before
    // other frontends start to send data.
    for (auto id : _active_ids) {
        // Send other id's rdma info to added_id
        if (id == _updating_id) {
            continue;
        }
        
        // Send added_id's rdma info to other id
        std::string update_msg;
        update_msg.append(1, static_cast<char>(UPDATE_RDMA_INFO));
        update_msg.append(1, static_cast<char>(1));
        update_msg.append(1, static_cast<char>(id));
        RDMAInfo_t rdma_info = _id_2_rdma_info[_updating_id][id];
        char* info_ptr = reinterpret_cast<char*>(&rdma_info);
        update_msg.append(info_ptr, sizeof(RDMAInfo_t));
        int other_fd = _id_2_socket_fd[id];
        if (send(other_fd, update_msg.c_str(), update_msg.size(), 0) < 0) {
            throw std::runtime_error("Failed to send update rdma info message");
        }
    }
    
    _state = WAIT_RDMA_INIT;
}

void FrontendController_t::_main_loop() {
    char recv_buffer[1600];
    while(!_exit_flag) {
        epoll_event events[MAX_EPOLL_EVENTS];
        int nfds = epoll_wait(_epoll_fd, events, MAX_EPOLL_EVENTS, 1000);
        if (nfds < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error("Failed to wait on epoll");
        }
        for (int n = 0; n < nfds; n++) {
            if (events[n].data.fd == _socket_fd) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                
                int conn_fd = accept(_socket_fd, (struct sockaddr*)&client_addr, &client_len);
                if (conn_fd < 0) {
                    throw std::runtime_error("Failed to accept connection");
                }
                std::string ip = inet_ntoa(client_addr.sin_addr);
                struct epoll_event ev;
                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = conn_fd;
                if (epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev) < 0) {
                    throw std::runtime_error("Failed to add connection to epoll");
                }
                assert(_idle_ids.size() > 0);
                uint8_t id = *_idle_ids.begin();
                _idle_ids.erase(id);
                _socket_fd_2_id[conn_fd] = id;
                _id_2_socket_fd[id] = conn_fd;
                _id_2_egress_port[id] = _ip_2_egress_port[ip];
                std::unordered_map<uint8_t, EgressPortEntry_t> crc_2_egressportentry;
                if (_state == INIT) {
                    _id_2_crcs[id] = std::vector<uint8_t>();
                    for (uint8_t crc = 0; crc < 256; crc++) {
                        _id_2_crcs[id].push_back(crc);
                        crc_2_egressportentry[crc] = _ip_2_egress_port[ip];
                    }
                    _state = NORMAL;
                } else {
                    _id_2_egress_port[id] = _ip_2_egress_port[ip];
                    _add_frontend(id);
                }
                // TODO: send other init info
                _active_ids.insert(id);
            } else if(events[n].data.u32 == TIMER_PRESENTOR) {
                uint64_t expirations;
                ssize_t recv_size = read(events[n].data.fd, &expirations, sizeof(expirations));
                if (recv_size == -1) {
                    throw std::runtime_error("Failed to read timerfd");
                }
                if (epoll_ctl(_epoll_fd, EPOLL_CTL_DEL, events[n].data.fd, NULL) == -1) {
                    throw std::runtime_error("Failed to remove timerfd from epoll");
                }
                close(events[n].data.fd);
                if (_state == WAIT_SYNC) {
                    _state = NORMAL;
                    _client->finish_updating();
                }
            }
            else {
                int conn_fd = events[n].data.fd;
                uint8_t id = _socket_fd_2_id[conn_fd];
                ssize_t recv_size = recv(conn_fd, recv_buffer, sizeof(recv_buffer), 0);
                if (recv_size < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        throw std::runtime_error("Failed to receive message");
                    }
                }
                else if (recv_size == 0) {
                    _remove_frontend(id);
                }
                else {
                    OperationType_t op_type = static_cast<OperationType_t>(recv_buffer[0]);
                    switch (op_type) {
                        case(OperationType_t::UPDATE_RDMA_INFO): {
                            uint8_t num_update = recv_buffer[1];
                            size_t now_bytes = 2;
                            for (uint8_t i = 0; i < num_update; ++i) {
                                uint8_t remote_id = recv_buffer[now_bytes];
                                now_bytes++;
                                _id_2_rdma_info[id][remote_id] = RDMAInfo_t();
                                memcpy(&_id_2_rdma_info[id][remote_id], recv_buffer + now_bytes, sizeof(RDMAInfo_t));
                                now_bytes += sizeof(RDMAInfo_t);
                            }
                            _wait_rdma_info_ids.erase(id);
                            _wait_init_ids.insert(id);
                            assert(_state == WAIT_RDMA_INFO);
                            if (_wait_rdma_info_ids.size() == 0) {
                                _update_rdma_info();
                            }
                            break;
                        }
                        case (OperationType_t::RDMA_STOP): {
                            uint8_t stop_id = recv_buffer[1];
                            _remove_frontend(stop_id);
                            break;
                        }
                        case (OperationType_t::OFFLOAD_ENTRIES): {
                            uint8_t add_size = recv_buffer[1];
                            uint8_t del_size = recv_buffer[2];
                            size_t now_bytes = 3;
                            std::vector<MiresgaOFTEntry_t> add_entries(reinterpret_cast<MiresgaOFTEntry_t*>(recv_buffer + now_bytes), 
                                                                      reinterpret_cast<MiresgaOFTEntry_t*>(recv_buffer + now_bytes + add_size * sizeof(MiresgaOFTEntry_t)));
                            now_bytes += add_size * sizeof(MiresgaOFTEntry_t);
                            std::vector<MiresgaOFTKey_t> del_keys(reinterpret_cast<MiresgaOFTKey_t*>(recv_buffer + now_bytes), 
                                                                  reinterpret_cast<MiresgaOFTKey_t*>(recv_buffer + now_bytes + del_size * sizeof(MiresgaOFTKey_t)));
                            _client->add_offload_entries(add_entries);
                            _client->del_offload_entries(del_keys);
                            break;
                        }
                        case (OperationType_t::COMPLETE): {
                            if (_state == WAIT_RDMA_INIT) {
                                _wait_init_ids.erase(id);
                                if (_wait_init_ids.size() == 0) {
                                    std::string added_start_msg = "";\
                                    added_start_msg.append(1, static_cast<char>(RDMA_START));
                                    added_start_msg.append(1, static_cast<char>(_active_ids.size() - 1));
                                    for (auto& id : _active_ids) {
                                        added_start_msg.append(1, static_cast<char>(id));
                                        std::string start_msg = "";
                                        start_msg.append(1, static_cast<char>(RDMA_START));
                                        start_msg.append(1, static_cast<char>(1));
                                        start_msg.append(1, static_cast<char>(id));
                                        int other_fd = _id_2_socket_fd[id];
                                        if (send(other_fd, start_msg.c_str(), start_msg.size(), 0) < 0) {
                                            throw std::runtime_error("Failed to send rdma start message");
                                        }
                                        std::string sync_msg = "";
                                        sync_msg.append(1, static_cast<char>(SYNC_OLD_DATA));
                                        sync_msg.append(1, static_cast<char>(id));
                                        sync_msg.append(1, static_cast<char>(_id_2_need_changed_crcs[id].size()));
                                        sync_msg.append(reinterpret_cast<const char*>(_id_2_need_changed_crcs[id].data()), _id_2_need_changed_crcs[id].size());
                                        if (send(other_fd, sync_msg.c_str(), sync_msg.size(), 0) < 0) {
                                            throw std::runtime_error("Failed to send sync old data message");
                                        }
                                    }
                                    int added_fd = _id_2_socket_fd[_updating_id];
                                    if (send(added_fd, added_start_msg.c_str(), added_start_msg.size(), 0) < 0) {
                                        throw std::runtime_error("Failed to send rdma start message");
                                    }
                                    _state = WAIT_SYNC;
                                    _id_2_need_changed_crcs.clear();
                                    int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
                                    if (timer_fd == -1) {
                                        throw std::runtime_error("Failed to create timerfd");
                                    }
                                    itimerspec new_value;
                                    new_value.it_value.tv_sec = 0;
                                    new_value.it_value.tv_nsec = 100000000; // 100 ms
                                    new_value.it_interval.tv_sec = 0;
                                    new_value.it_interval.tv_nsec = 0;
                                    if (timerfd_settime(timer_fd, 0, &new_value, nullptr) == -1) {
                                        throw std::runtime_error("Failed to set timerfd");
                                    }
                                    epoll_event ev;
                                    ev.events = EPOLLIN;
                                    ev.data.u32 = TIMER_PRESENTOR;
                                    ev.data.fd = timer_fd;
                                    if (epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev) == -1) {
                                        throw std::runtime_error("Failed to add timerfd to epoll");
                                    }

                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
}

void FrontendController_t::start() {
    _exit_flag = false;
    _controller_thread = std::thread(&FrontendController_t::_main_loop, this);
    _controller_thread.detach();
}

void FrontendController_t::stop() {
    _exit_flag = true;
}

FrontendController_t::FrontendController_t() {
    _socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (_socket_fd < 0) {
        throw std::runtime_error("Failed to create socket");
    }
    int opt = 1;
    if (setsockopt(_socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        throw std::runtime_error("Failed to set socket options");
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(9999);
    if (bind(_socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        throw std::runtime_error("Failed to bind socket");
    }
    if (listen(_socket_fd, 10) < 0) {
        throw std::runtime_error("Failed to listen on socket");
    }
    _epoll_fd = epoll_create1(0);
    if (_epoll_fd < 0) {
        throw std::runtime_error("Failed to create epoll instance");
    }
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = _socket_fd;
    if (epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, _socket_fd, &ev) < 0) {
        throw std::runtime_error("Failed to add socket to epoll");
    }
    _client = SwitchClient_t::get_instance();
    _state = INIT;
    for (int i = 0; i < 256; ++i) {
        _idle_ids.insert(i);
    }
    // TODO: initialize _ip_port_2_egress_port
    // TODO: initialize _rule_table
    // May need to read from config file
}

FrontendController_t::~FrontendController_t() {
    stop();
    close(_socket_fd);
    close(_epoll_fd);
    for (const auto& [fd, id] : _socket_fd_2_id) {
        close(fd);
    }
    _controller_thread.join();
}

FrontendController_t* FrontendController_t::get_instance() {
    if (_instance == nullptr) {
        _instance = new FrontendController_t();
    }
    return _instance;
}