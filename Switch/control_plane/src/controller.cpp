#include "controller.h"

static auto logger = spdlog::stdout_color_mt("controller");

std::string 
FrontendController_t::_serializing_rule_table() {
    std::string msg;
    msg.append(1, static_cast<char>(OperationType_t::UPDATE_RULE));
    msg.append(1, static_cast<char>(_rule_table.size()));
    msg.append(1, static_cast<char>(0));
    for (const auto& [key, rule_entry] : _rule_table) {
        msg.append(key);
        msg.append(1, '\0');
        msg.append(1, static_cast<char>(rule_entry.d_index));
        msg.append(1, static_cast<char>(rule_entry.offload_flag));
    }
    return msg;
}

std::string 
FrontendController_t::_serializing_d_index_table() {
    std::string msg;
    msg.append(1, static_cast<char>(OperationType_t::UPDATE_D_INDEX));
    msg.append(1, static_cast<char>(_d_index_2_backend_server_info.size()));
    msg.append(1, static_cast<char>(0));
    for (const auto& [d_index, server_info] : _d_index_2_backend_server_info) {
        msg.append(1, static_cast<char>(d_index));
        msg.append(reinterpret_cast<const char*>(&server_info), sizeof(ServerInfo_t));
    }
    return msg;
}

std::string 
FrontendController_t::_serializing_v_info() {
    std::string msg;
    msg.append(1, static_cast<char>(OperationType_t::UPDATE_V_INFO));
    msg.append(reinterpret_cast<const char*>(&_virtual_server_info), sizeof(ServerInfo_t));
    return msg;
}

void 
FrontendController_t::_add_frontend(
    uint8_t id
) {
    SPDLOG_LOGGER_INFO(logger, "Adding frontend: {}", id);
    _updating_id = id;
    size_t num_active_id = _active_ids.size();
    std::unordered_map<uint8_t, EgressPortEntry_t> crc_2_egressportentry;
    // If no active id, just add all crcs to this id. And no need to sync data or start RDMA.
    if (num_active_id == 0) {
        _id_2_num_crcs[id] = 256;
        for (int crc = 0; crc < 256; crc++) {
            crc_2_egressportentry[static_cast<uint8_t>(crc)] = _id_2_egress_port[id];
        }
        _active_ids.push_back(id);
        _state = NORMAL;
        _client->start_updating(crc_2_egressportentry);
        _client->finish_updating();
        return;
    }
    size_t num_each_if_add_crcs = 256 / (num_active_id + 1);
    _id_2_sync_crcs[id] = std::unordered_map<uint8_t, std::vector<uint8_t>>();
    if (num_active_id == 1) {
        uint8_t other_id = _active_ids[0];
        _id_2_sync_crcs[id] = std::unordered_map<uint8_t, std::vector<uint8_t>>();
        _id_2_sync_crcs[other_id] = std::unordered_map<uint8_t, std::vector<uint8_t>>();
        _id_2_sync_crcs[other_id][id] = std::vector<uint8_t>();
        _id_2_sync_crcs[id][other_id] = std::vector<uint8_t>();
        for (size_t i = 0; i < num_each_if_add_crcs; ++i) {
            _id_2_sync_crcs[id][other_id].push_back(i);
            _id_2_sync_crcs[other_id][id].push_back(i + num_each_if_add_crcs);
        }
        _id_2_num_crcs[id] = 128;
        _id_2_num_crcs[other_id] = 128;
        _id_2_need_changed_crcs[other_id] = _id_2_sync_crcs[id][other_id];
    } else {
        size_t num_if_add_extra = 256 % (num_active_id + 1);
        size_t num_each_if_not_add_crcs = 256 / num_active_id;
        size_t extra = 256 % num_active_id;
        // Update sync map;
        // Each active id gives some crcs to new id.
        for (size_t idx = 0; idx < num_active_id; ++idx) {
            // Calculate how many crcs this active id should give to new id
            uint8_t other_id = _active_ids[idx];
            size_t target_crc_size = num_each_if_add_crcs;
            if (idx < num_if_add_extra) {
                target_crc_size++;
            }
            size_t need_remove_size = _id_2_num_crcs[other_id] - target_crc_size;
            // From each sync_crcs remove some crcs to new id
            size_t num_each_sync_crcs_remove = need_remove_size / (num_active_id - 1);
            size_t extra_sync = need_remove_size % (num_active_id - 1);
            _id_2_sync_crcs[id][other_id] = std::vector<uint8_t>();
            _id_2_sync_crcs[other_id][id] = std::vector<uint8_t>();
            size_t num_each_sync_crcs = target_crc_size / num_active_id;
            size_t extra_each_sync = target_crc_size % num_active_id;
            for (size_t j = 0; j < num_active_id - 1; ++j) {
                size_t new_idx = (idx + 1 + j) % num_active_id;
                uint8_t sync_id = _active_ids[new_idx];
                size_t remove_size = num_each_sync_crcs_remove;
                if (j < extra_sync) {
                    remove_size++;
                }
                _id_2_sync_crcs[id][other_id].insert(_id_2_sync_crcs[id][other_id].end(), 
                                                     _id_2_sync_crcs[other_id][sync_id].begin(),
                                                     _id_2_sync_crcs[other_id][sync_id].begin() + remove_size);
                _id_2_sync_crcs[other_id][sync_id].erase(_id_2_sync_crcs[other_id][sync_id].begin(),
                                                         _id_2_sync_crcs[other_id][sync_id].begin() + remove_size);
                size_t target_size = num_each_sync_crcs;
                if (j < extra_each_sync) {
                    target_size++;
                }
                size_t now_sync_size = _id_2_sync_crcs[other_id][sync_id].size();
                assert(now_sync_size >= target_size);
                size_t need_change_size = now_sync_size - target_size;
                if (need_change_size > 0) {
                    _id_2_sync_crcs[other_id][id].insert(_id_2_sync_crcs[other_id][id].end(),
                                                         _id_2_sync_crcs[other_id][sync_id].begin(),
                                                         _id_2_sync_crcs[other_id][sync_id].begin() + need_change_size);
                    _id_2_sync_crcs[other_id][sync_id].erase(_id_2_sync_crcs[other_id][sync_id].begin(),
                                                             _id_2_sync_crcs[other_id][sync_id].begin() + need_change_size);
                }
            }
            _id_2_need_changed_crcs[other_id] = _id_2_sync_crcs[id][other_id];
            _id_2_num_crcs[other_id] -= need_remove_size;
            _id_2_num_crcs[id] += need_remove_size;
        }
    }
    _active_ids.push_back(id);
    for (auto active_id : _active_ids) {
        std::string init_msg;
        init_msg.append(1, static_cast<char>(INIT_RDMA_ENGINE));
        int socket_fd = _id_2_socket_fd[active_id];
        if (active_id != id) {
            init_msg.append(1, static_cast<char>(1));
            init_msg.append(1, static_cast<char>(id));
        } else {
            init_msg.append(1, static_cast<char>(num_active_id));
            init_msg.append(reinterpret_cast<const char*>(_active_ids.data()), num_active_id);
        }
        SPDLOG_LOGGER_DEBUG(logger, "Sending init rdma engine message to {}", active_id);
        if (send(socket_fd, init_msg.c_str(), init_msg.size(), 0) < 0) {
            SPDLOG_LOGGER_ERROR(logger, "Failed to send init rdma engine message to {}: {}", active_id, init_msg);
            throw std::runtime_error("Failed to send init rdma engine message");
        }
        _wait_rdma_info_ids.insert(id);
    }
    for (auto [active_id, id_2_crc_map] : _id_2_sync_crcs) {
        SPDLOG_LOGGER_DEBUG(logger, "{}: ", active_id);
        for (auto [other_id, crcs] : id_2_crc_map) {
            SPDLOG_LOGGER_DEBUG(logger, "{}: {}", other_id, fmt::join(crcs, ","));
            for (auto crc : crcs) {
                crc_2_egressportentry[crc] = _id_2_egress_port[active_id];
            }
        }
    }
    SPDLOG_LOGGER_DEBUG(logger, "Sending start updating message to client");
    _client->start_updating(crc_2_egressportentry);
    _state = WAIT_RDMA_INFO;
}

void 
FrontendController_t::_remove_frontend(
    uint8_t id
) {
    SPDLOG_LOGGER_INFO(logger, "Removing frontend: {}", id);
    auto it = std::find(_active_ids.begin(), _active_ids.end(), id);
    if (it == _active_ids.end()) {
        // Maybe already removed, do not throw error.
        return;
    }
    _active_ids.erase(it);
    int fd = _id_2_socket_fd[id];
    if (epoll_ctl(_epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to remove connection from epoll");
        throw std::runtime_error("Failed to remove connection from epoll");
    }
    close(fd);
    _socket_fd_2_id.erase(fd);
    _id_2_socket_fd.erase(id);
    _idle_ids.push(id);
    size_t num_crc = _id_2_num_crcs[id];
    size_t num_active_id = _active_ids.size();
    if (num_active_id == 0) {
        SPDLOG_LOGGER_INFO(logger, "All frontends disconnected, reset to INIT state");
        _state = INIT;
        _client->start_updating({});
        _client->finish_updating();
    } else if(num_active_id > 1){
        for (size_t idx = 0; idx < num_active_id; ++idx) {
            std::string stop_msg;
            stop_msg.append(1, static_cast<char>(RDMA_STOP));
            stop_msg.append(1, static_cast<char>(id));
            stop_msg.append(1, static_cast<char>(0));
            size_t need_update = 0;
            uint8_t other_id = _active_ids[idx];
            SPDLOG_LOGGER_DEBUG(logger, "Sending rdma stop message to {}: {}", other_id, id);
            _id_2_num_crcs[other_id] += _id_2_sync_crcs[id][other_id].size();
            size_t num_crc = _id_2_sync_crcs[id][other_id].size();
            size_t target_each_sync_crcs = _id_2_num_crcs[other_id] / (num_active_id - 1);
            size_t extra = _id_2_num_crcs[other_id] % (num_active_id - 1);
            size_t offset = 0;
            for (size_t j = 0; j < num_active_id - 1; ++j) {
                size_t new_idx = (idx + 1 + j) % num_active_id;
                uint8_t sync_id = _active_ids[new_idx];
                size_t target_size = target_each_sync_crcs;
                if (j < extra) {
                    target_size++;
                }
                size_t need_add_size = target_size - _id_2_sync_crcs[other_id][sync_id].size();
                if(need_add_size > 0) {
                    need_update++;
                    stop_msg.append(1, static_cast<char>(sync_id));
                    stop_msg.append(1, static_cast<char>(need_add_size));
                    _id_2_sync_crcs[other_id][sync_id].insert(_id_2_sync_crcs[other_id][sync_id].end(),
                                                              _id_2_sync_crcs[id][other_id].begin() + offset,
                                                              _id_2_sync_crcs[id][other_id].begin() + offset + need_add_size);
                    offset += need_add_size;
                }
            }
            stop_msg[2] = static_cast<char>(need_update);
            int other_fd = _id_2_socket_fd[other_id];
            if (send(other_fd, stop_msg.c_str(), stop_msg.size(), 0) < 0) {
                SPDLOG_LOGGER_ERROR(logger, "Failed to send rdma stop message to {}: {}", other_id, stop_msg);
                throw std::runtime_error("Failed to send rdma stop message");
            }
        }
        std::unordered_map<uint8_t, EgressPortEntry_t> crc_2_egressportentry;
        for (auto [active_id, id_2_crc_map] : _id_2_sync_crcs) {
            SPDLOG_LOGGER_DEBUG(logger, "{}: ", active_id);
            for (auto [other_id, crcs] : id_2_crc_map) {
                for (auto crc : crcs) {
                    SPDLOG_LOGGER_DEBUG(logger, "{}: {}", other_id, fmt::join(crcs, ","));
                    crc_2_egressportentry[crc] = _id_2_egress_port[active_id];
                }
            }
        }
        _id_2_sync_crcs.erase(id);
        _client->start_updating(crc_2_egressportentry);
        _client->finish_updating();
    } else {
        _id_2_sync_crcs.clear();
        std::string stop_msg;
        uint8_t last_id = *_active_ids.begin();
        std::unordered_map<uint8_t, EgressPortEntry_t> crc_2_egressportentry;
        _id_2_num_crcs[last_id] = 256;
        for (int crc = 0; crc < 256; crc++) {
            crc_2_egressportentry[crc] = _id_2_egress_port[last_id];
        }
        _client->start_updating(crc_2_egressportentry);
        _client->finish_updating();
        stop_msg.append(1, static_cast<char>(RDMA_STOP));
        stop_msg.append(1, static_cast<char>(id));
        stop_msg.append(1, static_cast<char>(0));
        // Do not need to update crcs since there is only one frontend left.
        if (send(_id_2_socket_fd[last_id], stop_msg.c_str(), stop_msg.size(), 0) < 0) {
            SPDLOG_LOGGER_ERROR(logger, "Failed to send rdma stop message to {}: {}", last_id, stop_msg);
            throw std::runtime_error("Failed to send rdma stop message");
        }
    }
    _id_2_num_crcs.erase(id);
    _id_2_need_changed_crcs.erase(id);
    _id_2_rdma_info.erase(id);
    _id_2_egress_port.erase(id);
}

void 
FrontendController_t::_update_rdma_info() {
    assert(_state == WAIT_RDMA_INFO);
    SPDLOG_LOGGER_DEBUG(logger, "Updating RDMA info");
    std::string add_msg;
    add_msg.append(1, static_cast<char>(UPDATE_RDMA_INFO));
    add_msg.append(1, static_cast<char>(_active_ids.size() - 1));
    for (auto id : _active_ids) {
        if (id == _updating_id) {
            continue;
        }
        SPDLOG_LOGGER_DEBUG(logger, "Updating RDMA info for {}: {}", _updating_id, id);
        SPDLOG_LOGGER_DEBUG(logger, "gid: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}, qpn: 0x{:x}, addr: 0x{:x}, rkey: 0x{:x}",
                            _id_2_rdma_info[id][_updating_id].gid[0], _id_2_rdma_info[id][_updating_id].gid[1], _id_2_rdma_info[id][_updating_id].gid[2], _id_2_rdma_info[id][_updating_id].gid[3],
                            _id_2_rdma_info[id][_updating_id].gid[4], _id_2_rdma_info[id][_updating_id].gid[5], _id_2_rdma_info[id][_updating_id].gid[6], _id_2_rdma_info[id][_updating_id].gid[7],
                            _id_2_rdma_info[id][_updating_id].gid[8], _id_2_rdma_info[id][_updating_id].gid[9], _id_2_rdma_info[id][_updating_id].gid[10], _id_2_rdma_info[id][_updating_id].gid[11],
                            _id_2_rdma_info[id][_updating_id].gid[12], _id_2_rdma_info[id][_updating_id].gid[13], _id_2_rdma_info[id][_updating_id].gid[14], _id_2_rdma_info[id][_updating_id].gid[15],
                            _id_2_rdma_info[id][_updating_id].qpn, _id_2_rdma_info[id][_updating_id].addr, _id_2_rdma_info[id][_updating_id].rkey);
        SPDLOG_LOGGER_DEBUG(logger, "Sync CRCs: {}", fmt::join(_id_2_sync_crcs[_updating_id][id], ","));
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
        SPDLOG_LOGGER_ERROR(logger, "Failed to send add rdma info message to {}: {}", _updating_id, add_msg);
        throw std::runtime_error("Failed to send add rdma info message");
    }
    // Update other frontends.
    // Note: Actually, one for loop can handle all the sending tasks. We divide it into two 
    // for loops to make sure the added frontend can initialize all its RDMA connections before
    // other frontends start to send data.
    for (auto id : _active_ids) {
        if (id == _updating_id) {
            continue;
        }
        // Send added_id's rdma info to other id
        SPDLOG_LOGGER_DEBUG(logger, "Sending update rdma info message to {}: {}", id, _updating_id);
        std::string update_msg;
        update_msg.append(1, static_cast<char>(UPDATE_RDMA_INFO));
        update_msg.append(1, static_cast<char>(1));
        update_msg.append(1, static_cast<char>(_updating_id));
        update_msg.append(1, static_cast<char>(_id_2_sync_crcs[id][_updating_id].size()));
        update_msg.append(reinterpret_cast<char*>(_id_2_sync_crcs[id][_updating_id].data()), _id_2_sync_crcs[id][_updating_id].size());
        RDMAInfo_t rdma_info = _id_2_rdma_info[_updating_id][id];
        char* info_ptr = reinterpret_cast<char*>(&rdma_info);
        SPDLOG_LOGGER_DEBUG(logger, "gid: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}, qpn: 0x{:x}, addr: 0x{:x}, rkey: 0x{:x}",
                            rdma_info.gid[0], rdma_info.gid[1], rdma_info.gid[2], rdma_info.gid[3], rdma_info.gid[4], rdma_info.gid[5], rdma_info.gid[6], rdma_info.gid[7],
                            rdma_info.gid[8], rdma_info.gid[9], rdma_info.gid[10], rdma_info.gid[11], rdma_info.gid[12], rdma_info.gid[13], rdma_info.gid[14], rdma_info.gid[15],
                            rdma_info.qpn, rdma_info.addr, rdma_info.rkey);
        SPDLOG_LOGGER_DEBUG(logger, "Sync CRCs: {}", fmt::join(_id_2_sync_crcs[id][_updating_id], ","));
        update_msg.append(info_ptr, sizeof(RDMAInfo_t));
        int other_fd = _id_2_socket_fd[id];
        if (send(other_fd, update_msg.c_str(), update_msg.size(), 0) < 0) {
            SPDLOG_LOGGER_ERROR(logger, "Failed to send update rdma info message to {}: {}", id, _updating_id);
            throw std::runtime_error("Failed to send update rdma info message");
        }
    }
    _state = WAIT_RDMA_INIT;
}

void 
FrontendController_t::_main_loop() {
    SPDLOG_LOGGER_DEBUG(logger, "Starting main loop");
    char recv_buffer[1600];
    while(!_exit_flag) {
        epoll_event events[MAX_EPOLL_EVENTS];
        int nfds = epoll_wait(_epoll_fd, events, MAX_EPOLL_EVENTS, 1000);
        if (nfds < 0) {
            if (errno == EINTR) {
                SPDLOG_LOGGER_DEBUG(logger, "Interrupted by signal");
                continue;
            }
            SPDLOG_LOGGER_ERROR(logger, "Failed to wait on epoll");
            throw std::runtime_error("Failed to wait on epoll");
        }
        for (int n = 0; n < nfds; n++) {
            if (events[n].data.fd == _socket_fd) {
                SPDLOG_LOGGER_DEBUG(logger, "New connection accepted");
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                
                int conn_fd = accept(_socket_fd, (struct sockaddr*)&client_addr, &client_len);
                if (conn_fd < 0) {
                    SPDLOG_LOGGER_ERROR(logger, "Failed to accept connection");
                    throw std::runtime_error("Failed to accept connection");
                }
                std::string ip = inet_ntoa(client_addr.sin_addr);
                SPDLOG_LOGGER_DEBUG(logger, "New connection accepted from {}: {}", ip, ntohs(client_addr.sin_port));
                struct epoll_event ev;
                ev.events = EPOLLIN;
                ev.data.fd = conn_fd;
                if (epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev) < 0) {
                    SPDLOG_LOGGER_ERROR(logger, "Failed to add connection to epoll");
                    throw std::runtime_error("Failed to add connection to epoll");
                }
                assert(_idle_ids.size() > 0);
                uint8_t id = _idle_ids.front();
                _idle_ids.pop();
                _socket_fd_2_id[conn_fd] = id;
                _id_2_socket_fd[id] = conn_fd;
                _id_2_egress_port[id] = _ip_2_egress_port[ip];
                SPDLOG_LOGGER_DEBUG(logger, "Sending rule table to {}: {}", id, ip);
                std::string rule_msg = _serializing_rule_table();
                if (send(conn_fd, rule_msg.c_str(), rule_msg.size(), 0) < 0) {
                    SPDLOG_LOGGER_ERROR(logger, "Failed to send rule table");
                    throw std::runtime_error("Failed to send rule table");
                }
                _state = WAIT_INIT_DINDEX;
            } else if(events[n].data.u32 == TIMER_PRESENTOR) {
                uint64_t expirations;
                SPDLOG_LOGGER_DEBUG(logger, "Reading timerfd");
                ssize_t recv_size = read(_timer_fd, &expirations, sizeof(expirations));
                if (recv_size == -1) {
                    SPDLOG_LOGGER_ERROR(logger, "Failed to read timerfd");
                    throw std::runtime_error("Failed to read timerfd");
                }
                if (_state == WAIT_SYNC) {
                    _state = NORMAL;
                    SPDLOG_LOGGER_DEBUG(logger, "Finishing updating");
                    _client->finish_updating();
                }
            }
            else {
                int conn_fd = events[n].data.fd;
                uint8_t id = _socket_fd_2_id[conn_fd];
                ssize_t recv_size = recv(conn_fd, recv_buffer, sizeof(recv_buffer), 0);
                if (recv_size < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        SPDLOG_LOGGER_ERROR(logger, "Failed to receive message, {}", strerror(errno));
                        throw std::runtime_error("Failed to receive message");
                    }
                }
                else if (recv_size == 0) {
                    SPDLOG_LOGGER_DEBUG(logger, "Removing frontend: {}", id);
                    _remove_frontend(id);
                }
                else {
                    OperationType_t op_type = static_cast<OperationType_t>(recv_buffer[0]);
                    SPDLOG_LOGGER_DEBUG(logger, "Operation type: {}", static_cast<uint8_t>(op_type));
                    switch (op_type) {
                        case(OperationType_t::UPDATE_RDMA_INFO): {
                            uint8_t num_update = recv_buffer[1];
                            size_t now_bytes = 2;
                            for (uint8_t i = 0; i < num_update; ++i) {
                                uint8_t remote_id = recv_buffer[now_bytes];
                                now_bytes++;
                                SPDLOG_LOGGER_DEBUG(logger, "Get RDMA info from {}: {}", id, remote_id);
                                _id_2_rdma_info[id][remote_id] = RDMAInfo_t();
                                memcpy(&_id_2_rdma_info[id][remote_id], recv_buffer + now_bytes, sizeof(RDMAInfo_t));
                                SPDLOG_LOGGER_DEBUG(logger, "gid: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}, qpn: 0x{:x}, addr: 0x{:x}, rkey: 0x{:x}",
                                                    _id_2_rdma_info[id][remote_id].gid[0], _id_2_rdma_info[id][remote_id].gid[1], _id_2_rdma_info[id][remote_id].gid[2], _id_2_rdma_info[id][remote_id].gid[3],
                                                    _id_2_rdma_info[id][remote_id].gid[4], _id_2_rdma_info[id][remote_id].gid[5], _id_2_rdma_info[id][remote_id].gid[6], _id_2_rdma_info[id][remote_id].gid[7],
                                                    _id_2_rdma_info[id][remote_id].gid[8], _id_2_rdma_info[id][remote_id].gid[9], _id_2_rdma_info[id][remote_id].gid[10], _id_2_rdma_info[id][remote_id].gid[11],
                                                    _id_2_rdma_info[id][remote_id].gid[12], _id_2_rdma_info[id][remote_id].gid[13], _id_2_rdma_info[id][remote_id].gid[14], _id_2_rdma_info[id][remote_id].gid[15],
                                                    _id_2_rdma_info[id][remote_id].qpn, _id_2_rdma_info[id][remote_id].addr, _id_2_rdma_info[id][remote_id].rkey);
                                now_bytes += sizeof(RDMAInfo_t);
                            }
                            _wait_rdma_info_ids.erase(id);
                            _wait_init_ids.insert(id);
                            assert(_state == WAIT_RDMA_INFO);
                            if (_wait_rdma_info_ids.size() == 0) {
                                SPDLOG_LOGGER_DEBUG(logger, "Updating RDMA info");
                                _update_rdma_info();
                            }
                            break;
                        }
                        case (OperationType_t::RDMA_STOP): {
                            uint8_t stop_id = recv_buffer[1];
                            SPDLOG_LOGGER_DEBUG(logger, "Removing frontend: {}", stop_id);
                            _remove_frontend(stop_id);
                            break;
                        }
                        case (OperationType_t::OFFLOAD_ENTRIES): {
                            SPDLOG_LOGGER_DEBUG(logger, "Adding offload entries");
                            uint8_t add_size = recv_buffer[1];
                            uint8_t del_size = recv_buffer[2];
                            size_t now_bytes = 3;
                            SPDLOG_LOGGER_DEBUG(logger, "Adding {} entries", add_size);
                            SPDLOG_LOGGER_DEBUG(logger, "Deleting {} entries", del_size);
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
                                    SPDLOG_LOGGER_DEBUG(logger, "Starting RDMA engines");
                                    std::string added_start_msg = "";
                                    added_start_msg.append(1, static_cast<char>(RDMA_START));
                                    added_start_msg.append(1, static_cast<char>(_active_ids.size() - 1));
                                    for (auto& id : _active_ids) {
                                        if (id == _updating_id) {
                                            continue;
                                        }
                                        added_start_msg.append(1, static_cast<char>(id));
                                        SPDLOG_LOGGER_DEBUG(logger, "Sending rdma start message to {}: {}", id, _updating_id);
                                        std::string start_msg = "";
                                        start_msg.append(1, static_cast<char>(RDMA_START));
                                        start_msg.append(1, static_cast<char>(1));
                                        start_msg.append(1, static_cast<char>(_updating_id));
                                        int other_fd = _id_2_socket_fd[id];
                                        if (send(other_fd, start_msg.c_str(), start_msg.size(), 0) < 0) {
                                            SPDLOG_LOGGER_ERROR(logger, "Failed to send rdma start message to {}: {}", id, _updating_id);
                                            throw std::runtime_error("Failed to send rdma start message");
                                        }
                                        std::string sync_msg = "";
                                        SPDLOG_LOGGER_DEBUG(logger, "Sending sync old data message to {}: {}", id, _updating_id);
                                        sync_msg.append(1, static_cast<char>(SYNC_OLD_DATA));
                                        sync_msg.append(1, static_cast<char>(_updating_id));
                                        sync_msg.append(1, static_cast<char>(_id_2_need_changed_crcs[id].size()));
                                        sync_msg.append(reinterpret_cast<const char*>(_id_2_need_changed_crcs[id].data()), _id_2_need_changed_crcs[id].size());
                                        SPDLOG_LOGGER_DEBUG(logger, "Sync CRCs: {}", fmt::join(_id_2_need_changed_crcs[id], ","));
                                        if (send(other_fd, sync_msg.c_str(), sync_msg.size(), 0) < 0) {
                                            SPDLOG_LOGGER_ERROR(logger, "Failed to send sync old data message to {}: {}", id, _updating_id);
                                            throw std::runtime_error("Failed to send sync old data message");
                                        }
                                    }
                                    SPDLOG_LOGGER_DEBUG(logger, "Sending rdma start message to {}", _updating_id);
                                    int added_fd = _id_2_socket_fd[_updating_id];
                                    if (send(added_fd, added_start_msg.c_str(), added_start_msg.size(), 0) < 0) {
                                        SPDLOG_LOGGER_ERROR(logger, "Failed to send rdma start message to {}: {}", _updating_id, _updating_id);
                                        throw std::runtime_error("Failed to send rdma start message");
                                    }
                                    _state = WAIT_SYNC;
                                    _id_2_need_changed_crcs.clear();
                                    SPDLOG_LOGGER_DEBUG(logger, "Setting timerfd");
                                    itimerspec new_value;
                                    new_value.it_value.tv_sec = 0;
                                    new_value.it_value.tv_nsec = 500000000; // 500 ms
                                    new_value.it_interval.tv_sec = 0;
                                    new_value.it_interval.tv_nsec = 0;
                                    if (timerfd_settime(_timer_fd, 0, &new_value, nullptr) == -1) {
                                        SPDLOG_LOGGER_ERROR(logger, "Failed to set timerfd");
                                        throw std::runtime_error("Failed to set timerfd");
                                    }
                                }
                            }
                            else if(_state == WAIT_INIT_DINDEX) {
                                SPDLOG_LOGGER_DEBUG(logger, "Sending d_index table to {}", id);
                                std::string d_index_msg = _serializing_d_index_table();
                                if (send(conn_fd, d_index_msg.c_str(), d_index_msg.size(), 0) < 0) {
                                    SPDLOG_LOGGER_ERROR(logger, "Failed to send d_index table");
                                    throw std::runtime_error("Failed to send d_index table");
                                }
                                _state = WAIT_INIT_VINFO;
                            } else if(_state == WAIT_INIT_VINFO) {
                                SPDLOG_LOGGER_DEBUG(logger, "Sending virtual server info to {}", id);
                                std::string v_info_msg = _serializing_v_info();
                                if (send(conn_fd, v_info_msg.c_str(), v_info_msg.size(), 0) < 0) {
                                    SPDLOG_LOGGER_ERROR(logger, "Failed to send virtual server info");
                                    throw std::runtime_error("Failed to send virtual server info");
                                }
                                _add_frontend(id);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    SPDLOG_LOGGER_DEBUG(logger, "Exit main loop");
}

void 
FrontendController_t::start() {
    _exit_flag = false;
    _controller_thread = std::thread(&FrontendController_t::_main_loop, this);
    _controller_thread.detach();
}

void 
FrontendController_t::stop() {
    _exit_flag = true;
}

FrontendController_t::FrontendController_t(
    std::string config_path
) {
    SPDLOG_LOGGER_INFO(logger, "Initializing Controller.");
    _timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (_timer_fd == -1) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to create timerfd");
        throw std::runtime_error("Failed to create timerfd");
    }
    _socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (_socket_fd < 0) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to create socket");
        throw std::runtime_error("Failed to create socket");
    }
    int opt = 1;
    if (setsockopt(_socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to set socket options");
        throw std::runtime_error("Failed to set socket options");
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(12345);
    if (bind(_socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to bind socket: {}", strerror(errno));
        throw std::runtime_error("Failed to bind socket");
    }
    if (listen(_socket_fd, 10) < 0) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to listen on socket");
        throw std::runtime_error("Failed to listen on socket");
    }
    _epoll_fd = epoll_create1(0);
    if (_epoll_fd < 0) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to create epoll instance");
        throw std::runtime_error("Failed to create epoll instance");
    }
    epoll_event socket_ev;
    socket_ev.events = EPOLLIN;
    socket_ev.data.fd = _socket_fd;
    if (epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, _socket_fd, &socket_ev) < 0) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to add socket to epoll");
        throw std::runtime_error("Failed to add socket to epoll");
    }
    epoll_event timer_ev;
    timer_ev.events = EPOLLIN;
    timer_ev.data.u32 = TIMER_PRESENTOR;
    if (epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, _timer_fd, &timer_ev) == -1) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to add timerfd to epoll");
        throw std::runtime_error("Failed to add timerfd to epoll");
    }
    _client = SwitchClient_t::get_instance();
    _state = INIT;
    for (int i = 0; i < 256; ++i) {
        _idle_ids.push(i);
    }
    std::ifstream config_file(config_path);
    assert(config_file.is_open());
    nlohmann::json config_json;
    config_file >> config_json;
    config_file.close();
    std::string src_mac_str = config_json["frontend_gateway_mac"];
    uint64_t src_mac = 0;
    std::stringstream src_ss(src_mac_str);
    std::string src_byte_str;
    while(std::getline(src_ss, src_byte_str, ':')) {
        src_mac = (src_mac << 8) | std::stoul(src_byte_str, nullptr, 16);
    }
    auto frontend_servers_info = config_json["frontend_servers_info"];
    assert(frontend_servers_info.is_array());
    for (const auto& server_info : frontend_servers_info) {
        std::string ip = server_info["client_ip"];
        std::string dst_mac_str = server_info["frontend_mac"];
        uint64_t dst_mac = 0;
        std::stringstream dst_ss(dst_mac_str);
        std::string dst_byte_str;
        while(std::getline(dst_ss, dst_byte_str, ':')) {
            dst_mac = (dst_mac << 8) | std::stoul(dst_byte_str, nullptr, 16);
        }
        uint64_t egress_port = server_info["egress_port"];
        EgressPortEntry_t egress_port_entry = {src_mac, dst_mac, egress_port};
        _ip_2_egress_port[ip] = egress_port_entry;
    }
    auto backend_servers_info = config_json["backend_servers_info"];
    assert(backend_servers_info.is_array());
    size_t d_index = 0;
    for (const auto& server_info : backend_servers_info) {
        auto rules = server_info["rules"];
        assert(rules.is_array());
        for (const auto& rule : rules) {
            RuleEntry_t rule_entry;
            rule_entry.d_index = d_index;
            rule_entry.offload_flag = rule["offload_flag"];
            std::string key = rule["key"];
            _rule_table[key] = rule_entry;
        }
        ServerInfo_t server_info_entry;
        server_info_entry.ip = inet_addr(server_info["ip"].get<std::string>().c_str());
        server_info_entry.port = htons(server_info["port"]);
        std::string mac_str = server_info["mac"];
        std::stringstream mac_ss(mac_str);
        std::string byte_str;
        int i = 0;
        while (std::getline(mac_ss, byte_str, ':')) {
            server_info_entry.mac[i] = std::stoi(byte_str, nullptr, 16);
            i++;
        }
        _d_index_2_backend_server_info[d_index] = server_info_entry;
        d_index++;
    }
    _virtual_server_info.ip = inet_addr(config_json["virtual_server_info"]["ip"].get<std::string>().c_str());
    _virtual_server_info.port = htons(config_json["virtual_server_info"]["port"]);
    std::string mac_str = config_json["virtual_server_info"]["mac"];
    std::stringstream mac_ss(mac_str);
    std::string byte_str;
    int i = 0;
    while (std::getline(mac_ss, byte_str, ':')) {
        _virtual_server_info.mac[i] = std::stoi(byte_str, nullptr, 16);
        i++;
    }
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

void 
FrontendController_t::init_frontend_controller(
    std::string config_path
) {
    if (_instance == nullptr) {
        _instance = new FrontendController_t(config_path);
    }
}

FrontendController_t* 
FrontendController_t::get_instance() {
    if (_instance == nullptr) {
        SPDLOG_LOGGER_ERROR(logger, "FrontendController_t is not initialized");
        throw std::runtime_error("FrontendController_t is not initialized");
    }
    return _instance;
}