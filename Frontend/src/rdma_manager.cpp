#include "rdma_manager.h"

static auto logger = spdlog::stdout_color_mt("RDMAManager");

RDMAManager::RDMAManager(const char* dev_name, int epoll_fd)
{
    struct ibv_device** dev_list = ibv_get_device_list(NULL);
    if (!dev_list) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to get IB devices list");
        throw std::runtime_error("Failed to get IB devices list");
    }

    struct ibv_device* ib_dev = nullptr;
    for (int i = 0; dev_list[i]; ++i) {
        if (!strcmp(ibv_get_device_name(dev_list[i]), dev_name)) {
            SPDLOG_LOGGER_DEBUG(logger, "Found IB device: {}", dev_name);
            ib_dev = dev_list[i];
            break;
        }
    }
    ibv_free_device_list(dev_list);
    if (!ib_dev) {
        SPDLOG_LOGGER_ERROR(logger, "IB device {} not found", dev_name);
        throw std::runtime_error("IB device not found");
    }

    SPDLOG_LOGGER_DEBUG(logger, "Opening IB device: {}", dev_name);
    _ctx = ibv_open_device(ib_dev);
    if (!_ctx) {
        SPDLOG_LOGGER_ERROR(logger, "Failed to open IB device");
        throw std::runtime_error("Failed to open IB device");
    }

    SPDLOG_LOGGER_DEBUG(logger, "Allocating Protection Domain");
    _pd = ibv_alloc_pd(_ctx);
    if (!_pd) {
        ibv_close_device(_ctx);
        SPDLOG_LOGGER_ERROR(logger, "Failed to allocate Protection Domain");
        throw std::runtime_error("Failed to allocate Protection Domain");
    }

    SPDLOG_LOGGER_DEBUG(logger, "Querying local GID");
    // Note: Here we assume using port 1. GID index 3 is for RoCE v2
    if (ibv_query_gid(_ctx, 1, 3, &_local_gid)) {
        ibv_dealloc_pd(_pd);
        ibv_close_device(_ctx);
        SPDLOG_LOGGER_ERROR(logger, "Failed to get local GID");
        throw std::runtime_error("Failed to get local GID");
    }

    SPDLOG_LOGGER_DEBUG(logger, "Local GID: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        _local_gid.raw[0], _local_gid.raw[1], _local_gid.raw[2], _local_gid.raw[3],
                        _local_gid.raw[4], _local_gid.raw[5], _local_gid.raw[6], _local_gid.raw[7],
                        _local_gid.raw[8], _local_gid.raw[9], _local_gid.raw[10], _local_gid.raw[11],
                        _local_gid.raw[12], _local_gid.raw[13], _local_gid.raw[14], _local_gid.raw[15]);

    SPDLOG_LOGGER_DEBUG(logger, "Creating Completion Channel");
    _comp_channel = ibv_create_comp_channel(_ctx);
    if (!_comp_channel) {
        ibv_dealloc_pd(_pd);
        ibv_close_device(_ctx);
        SPDLOG_LOGGER_ERROR(logger, "Failed to create Completion Channel");
        throw std::runtime_error("Failed to create Completion Channel");
    }

    SPDLOG_LOGGER_DEBUG(logger, "Creating Completion Queue");
    _cq = ibv_create_cq(_ctx, MAX_CQ_SIZE, nullptr, _comp_channel, 0);
    if (!_cq) {
        ibv_destroy_comp_channel(_comp_channel);
        ibv_dealloc_pd(_pd);
        ibv_close_device(_ctx);
        SPDLOG_LOGGER_ERROR(logger, "Failed to create Completion Queue");
        throw std::runtime_error("Failed to create Completion Queue");
    }

    SPDLOG_LOGGER_DEBUG(logger, "Requesting CQ notification");
    if (ibv_req_notify_cq(_cq, 0)) {
        ibv_destroy_cq(_cq);
        ibv_destroy_comp_channel(_comp_channel);
        ibv_dealloc_pd(_pd);
        ibv_close_device(_ctx);
        SPDLOG_LOGGER_ERROR(logger, "Failed to request CQ notification");
        throw std::runtime_error("Failed to request CQ notification");
    }

    SPDLOG_LOGGER_DEBUG(logger, "Adding CQ fd to epoll");
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.u32 = CQ_PRESENTER;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, _comp_channel->fd, &ev) == -1) {
        ibv_destroy_cq(_cq);
        ibv_destroy_comp_channel(_comp_channel);
        ibv_dealloc_pd(_pd);
        ibv_close_device(_ctx);
        SPDLOG_LOGGER_ERROR(logger, "Failed to add CQ fd to epoll");
        throw std::runtime_error("Failed to add CQ fd to epoll");
    }
}

RDMAManager::~RDMAManager()
{
    for (auto& pair : _id_2_engines) {
        delete pair.second.first;
    }
    ibv_destroy_comp_channel(_comp_channel);
    ibv_destroy_cq(_cq);
    ibv_dealloc_pd(_pd);
    ibv_close_device(_ctx);
}

void RDMAManager::init_rdma_manager(const char* dev_name, int epoll_fd) {
    if (_instance == nullptr) {
        SPDLOG_LOGGER_INFO(logger, "Initializing RDMAManager with device: {}", dev_name);
        _instance = new RDMAManager(dev_name, epoll_fd);
    }
}

RDMAManager* RDMAManager::get_instance() {
    if (_instance == nullptr) {
        SPDLOG_LOGGER_ERROR(logger, "RDMAManager not initialized");
        throw std::runtime_error("RDMAManager not initialized");
    }
    return _instance;
}

void RDMAManager::destroy_instance() {
    if (_instance != nullptr) {
        SPDLOG_LOGGER_WARN(logger, "Destroying RDMAManager instance");
        delete _instance;
        _instance = nullptr;
    }
}

std::string RDMAManager::add_engine(uint8_t id)
{
    SPDLOG_LOGGER_DEBUG(logger, "Adding RDMA engine with ID: {}", id);
    if (_id_2_engines.find(id) != _id_2_engines.end()) {
        SPDLOG_LOGGER_ERROR(logger, "Engine ID {} already exists", id);
        throw std::runtime_error("Engine ID already exists");
    }
    std::string msg;
    msg.resize(sizeof(RDMAInfo_t) + 1);
    msg[0] = static_cast<char>(id);
    RDMAEngine* engine = new RDMAEngine(id, _pd, _cq, _local_gid);
    _id_2_engines[id] = std::make_pair(engine, false);
    RDMAInfo_t* local_info = engine->get_local_rdma_info();
    SPDLOG_LOGGER_DEBUG(logger, "New RDMA Info - GID: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}, QPN: 0x{:x}, ADDR: 0x{:x}, RKEY: 0x{:x}",
                        local_info->gid.raw[0], local_info->gid.raw[1], local_info->gid.raw[2], local_info->gid.raw[3],
                        local_info->gid.raw[4], local_info->gid.raw[5], local_info->gid.raw[6], local_info->gid.raw[7],
                        local_info->gid.raw[8], local_info->gid.raw[9], local_info->gid.raw[10], local_info->gid.raw[11],
                        local_info->gid.raw[12], local_info->gid.raw[13], local_info->gid.raw[14], local_info->gid.raw[15],
                        local_info->qpn,
                        local_info->addr,
                        local_info->rkey);
    memcpy(msg.data() + 1, local_info, sizeof(RDMAInfo_t));
    return msg;
}

void RDMAManager::update_engine(uint8_t id, RDMAInfo_t* remote_rdma_info, std::vector<uint8_t> crcs)
{
    SPDLOG_LOGGER_DEBUG(logger, "Updating RDMA engine with ID: {}", id);
    SPDLOG_LOGGER_DEBUG(logger, "Remote RDMA Info - GID: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}, QPN: 0x{:x}, ADDR: 0x{:x}, RKEY: 0x{:x}",
                        remote_rdma_info->gid.raw[0], remote_rdma_info->gid.raw[1], remote_rdma_info->gid.raw[2], remote_rdma_info->gid.raw[3],
                        remote_rdma_info->gid.raw[4], remote_rdma_info->gid.raw[5], remote_rdma_info->gid.raw[6], remote_rdma_info->gid.raw[7],
                        remote_rdma_info->gid.raw[8], remote_rdma_info->gid.raw[9], remote_rdma_info->gid.raw[10], remote_rdma_info->gid.raw[11],
                        remote_rdma_info->gid.raw[12], remote_rdma_info->gid.raw[13], remote_rdma_info->gid.raw[14], remote_rdma_info->gid.raw[15],
                        remote_rdma_info->qpn,
                        remote_rdma_info->addr,
                        remote_rdma_info->rkey);
    SPDLOG_LOGGER_DEBUG(logger, "Sync CRCs for engine ID {}: {}", id, crcs);
    if (crcs.empty()) {
        SPDLOG_LOGGER_ERROR(logger, "No CRCs provided for engine ID {}", id);
        throw std::runtime_error("No CRCs provided");
    }
    for (uint8_t crc : crcs) {
        _crc_2_id[crc] = id;
    }
    auto it = _id_2_engines.find(id);
    if (it == _id_2_engines.end()) {
        SPDLOG_LOGGER_ERROR(logger, "Engine ID {} not found", id);
        throw std::runtime_error("Engine ID not found");
    }
    if (it->second.second) {
        SPDLOG_LOGGER_ERROR(logger, "Engine ID {} already started", id);
        throw std::runtime_error("Engine already started");
    }
    it->second.first->init_engine(remote_rdma_info);
}

void RDMAManager::remove_engine(uint8_t id, std::unordered_map<uint8_t, uint8_t>& crc_2_id)
{
    SPDLOG_LOGGER_DEBUG(logger, "Removing RDMA engine with ID: {}", id);
    for (auto _pair : crc_2_id) {
        _crc_2_id[_pair.first] = _pair.second;
    }
    auto it = _id_2_engines.find(id);
    if (it == _id_2_engines.end()) {
        SPDLOG_LOGGER_ERROR(logger, "Engine ID {} not found", id);
        return;
    }
    delete it->second.first;
    _id_2_engines.erase(it);
}

void RDMAManager::start_engine(uint8_t id)
{
    SPDLOG_LOGGER_DEBUG(logger, "Starting RDMA engine with ID: {}", id);
    auto it = _id_2_engines.find(id);
    if (it == _id_2_engines.end()) {
        SPDLOG_LOGGER_ERROR(logger, "Engine ID {} not found", id);
        throw std::runtime_error("Engine ID not found");
    }
    it->second.second = true;
}

void RDMAManager::sync_states() {
    for (auto& pair : _id_2_engines) {
        RDMAEngine* engine = pair.second.first;
        if (pair.second.second) {
            SPDLOG_LOGGER_DEBUG(logger, "Syncing RDMA engine {} states", pair.first);
            engine->sync_start();
        }
    }
}

void RDMAManager::add_flow_data(MiresgaOFTEntry_t* add_data) {
    if (add_data == nullptr) {
        SPDLOG_LOGGER_ERROR(logger, "Null flow data to add");
        throw std::runtime_error("Null flow data");
    }
    #ifdef DEBUG
    char ip_str[INET_ADDRSTRLEN];
    SPDLOG_LOGGER_DEBUG(logger, "Adding flow data: Key:({}:{} {:02x}), flow_state: {}, d_index: {}",
                        inet_ntop(AF_INET, &add_data->key.client_ip, ip_str, INET_ADDRSTRLEN), 
                        add_data->key.client_port, add_data->key.crc, add_data->key.crc,
                        add_data->data.flow_state, add_data->data.d_index);
    #endif
    uint8_t crc = add_data->key.crc;
    uint8_t id = _crc_2_id[crc];
    _id_2_engines[id].first->add_flow_data(add_data);
}

void RDMAManager::add_old_flow_data(uint8_t remote_id, std::vector<MiresgaOFTEntry_t>& add_data_vec) {
    if (add_data_vec.empty()) {
        SPDLOG_LOGGER_DEBUG(logger, "No flow data to add for remote ID: {}", remote_id);
        return;
    }
    SPDLOG_LOGGER_DEBUG(logger, "Adding {} old flow data entries for remote ID: {}", add_data_vec.size(), remote_id);
    _id_2_engines[remote_id].first->add_flow_data(add_data_vec);
}

void RDMAManager::del_flow_data(MiresgaOFTKey_t* del_data) {
    if (del_data == nullptr) {
        SPDLOG_LOGGER_ERROR(logger, "Null flow data to delete");
        throw std::runtime_error("Null flow data");
    }
    #ifdef DEBUG
    char ip_str[INET_ADDRSTRLEN];
    SPDLOG_LOGGER_DEBUG(logger, "Deleting flow data: Key:({}:{} {:02x})",
                        inet_ntop(AF_INET, &del_data->client_ip, ip_str, INET_ADDRSTRLEN), 
                        del_data->client_port, del_data->crc);
    #endif
    uint8_t crc = del_data->crc;
    uint8_t id = _crc_2_id[crc];
    _id_2_engines[id].first->del_flow_data(del_data);
}

std::vector<ibv_wc> RDMAManager::process_cqe()
{
    SPDLOG_LOGGER_DEBUG(logger, "Processing CQE");
    std::vector<ibv_wc> completions;
    if(ibv_get_cq_event(_comp_channel, &_cq, nullptr) == 0) {
        ibv_req_notify_cq(_cq, 0);
        int num_wc = 0;
        ibv_wc wc;
        do {
            num_wc = ibv_poll_cq(_cq, 1, &wc);
            if (num_wc > 0) {
                completions.push_back(wc);
            } else if (num_wc < 0) {
                SPDLOG_LOGGER_ERROR(logger, "Failed to poll CQ");
                throw std::runtime_error("Failed to poll CQ");
            }
        } while(num_wc != 0);
        ibv_ack_cq_events(_cq, 1);
    } else {
        SPDLOG_LOGGER_ERROR(logger, "Failed to get CQ event");
        throw std::runtime_error("Failed to get CQ event");
    }
    SPDLOG_LOGGER_DEBUG(logger, "Processed {} completions", completions.size());
    return completions;
}

void* RDMAManager::get_recv_addr(uint8_t id) {
    auto it = _id_2_engines.find(id);
    if (it == _id_2_engines.end()) {
        SPDLOG_LOGGER_ERROR(logger, "Engine ID {} not found", id);
        throw std::runtime_error("Engine ID not found");
    }
    return it->second.first->get_recv_addr();
}

void RDMAManager::sync_complete(uint8_t id) {
    auto it = _id_2_engines.find(id);
    if (it == _id_2_engines.end()) {
        SPDLOG_LOGGER_ERROR(logger, "Engine ID {} not found", id);
        throw std::runtime_error("Engine ID not found");
    }
    it->second.first->sync_complete();
}