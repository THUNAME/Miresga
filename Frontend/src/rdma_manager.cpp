#include "rdma_manager.h"

static auto logger = spdlog::stdout_color_mt("RDMAManager");

RDMAManager::RDMAManager(
    const char* dev_name, 
    int epoll_fd
) {
    _epoll_fd = epoll_fd;
    _flow_table = FlowTable::get_instance();
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
    epoll_event ev;
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
        delete pair.second;
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

__attribute__((always_inline)) 
std::string RDMAManager::add_engine(uint8_t id)
{
    SPDLOG_LOGGER_DEBUG(logger, "Adding RDMA engine with ID: {}", id);
    if (unlikely(_id_2_engines.find(id) != _id_2_engines.end())) {
        SPDLOG_LOGGER_ERROR(logger, "Engine ID {} already exists", id);
        throw std::runtime_error("Engine ID already exists");
    }
    std::string msg;
    msg.resize(sizeof(RDMAInfo_t) + 1);
    msg[0] = static_cast<char>(id);
    RDMAEngine* engine = new RDMAEngine(id, _pd, _cq, _local_gid, _epoll_fd);
    _id_2_engines[id] = engine;
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

__attribute__((always_inline))
void 
RDMAManager::update_engine(uint8_t id, RDMAInfo_t* remote_rdma_info)
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
    auto it = _id_2_engines.find(id);
    if (unlikely(it == _id_2_engines.end())) {
        SPDLOG_LOGGER_ERROR(logger, "Engine ID {} not found", id);
        throw std::runtime_error("Engine ID not found");
    }
    it->second->init_engine(remote_rdma_info);
}

__attribute__((always_inline)) 
void 
RDMAManager::update_crcs(std::unordered_map<uint8_t, std::vector<uint8_t>>& id_2_crcs)
{
    _updating_flag = true;
    SPDLOG_LOGGER_DEBUG(logger, "Updating CRC mappings for RDMA engines");
    _id_2_crcs = std::move(id_2_crcs);
    for (auto& [id, crcs] : _id_2_crcs) {
        SPDLOG_LOGGER_DEBUG(logger, "Engine ID {} handles CRCs: {}", id, fmt::join(crcs, ","));
        for (auto crc : crcs) {
            _crc_2_id[crc] = id;
        }
    }
    _updating_flag = false;
}

__attribute__((always_inline)) 
void 
RDMAManager::remove_engine(uint8_t id, std::unordered_map<uint8_t, std::vector<uint8_t>>& id_2_crcs)
{
    SPDLOG_LOGGER_DEBUG(logger, "Removing RDMA engine with ID: {}", id);
    _id_2_crcs.erase(id);
    for (auto [id, crcs] : _id_2_crcs) {
        id_2_crcs[id] = std::vector<uint8_t>(crcs);
        for (auto crc : crcs) {
            _crc_2_id[crc] = id;
        }
    }
    auto it = _id_2_engines.find(id);
    if (unlikely(it == _id_2_engines.end())) {
        SPDLOG_LOGGER_ERROR(logger, "Engine ID {} not found", id);
        return;
    }
    delete it->second;
    _id_2_engines.erase(it);
}

__attribute__((always_inline)) 
void 
RDMAManager::start_engine(uint8_t id)
{
    SPDLOG_LOGGER_DEBUG(logger, "Starting RDMA engine with ID: {}", id);
    auto it = _id_2_engines.find(id);
    if (unlikely(it == _id_2_engines.end())) {
        SPDLOG_LOGGER_ERROR(logger, "Engine ID {} not found", id);
        throw std::runtime_error("Engine ID not found");
    }
    // Set timerfd to start.
    it->second->sync_complete();
}

__attribute__((always_inline)) 
void 
RDMAManager::sync_states(uint8_t id) {
    auto it = _id_2_engines.find(id);
    if (it != _id_2_engines.end()) {
        if (_updating_flag) {
            SPDLOG_LOGGER_WARN(logger, "RDMA engine {} is already updating. Skipping sync_states.", id);
            it->second->sync_complete();
        } else {
            it->second->sync_start();
        }
    }
}

__attribute__((always_inline)) 
void 
RDMAManager::sync_complete(uint8_t id) {
    auto it = _id_2_engines.find(id);
    if (it != _id_2_engines.end()) {
        SPDLOG_LOGGER_DEBUG(logger, "Syncing complete for RDMA engine {}", id);
        it->second->sync_complete();
    }
}

__attribute__((always_inline)) 
std::vector<ibv_wc> 
RDMAManager::process_cqe()
{
    SPDLOG_LOGGER_DEBUG(logger, "Processing CQE");
    std::vector<ibv_wc> completions;
    ibv_cq* cq = nullptr;
    void* cq_context = nullptr;
    if(likely(ibv_get_cq_event(_comp_channel, &cq, &cq_context) == 0)) {
        ibv_ack_cq_events(cq, 1);
        ibv_req_notify_cq(cq, 0);
        int num_wc = 0;
        ibv_wc wc;
        do {
            num_wc = ibv_poll_cq(cq, 1, &wc);
            if (likely(num_wc > 0)) {
                completions.push_back(wc);
            } else if (unlikely(num_wc < 0)) {
                SPDLOG_LOGGER_ERROR(logger, "Failed to poll CQ");
                throw std::runtime_error("Failed to poll CQ");
            }
        } while(num_wc != 0);
    } else {
        SPDLOG_LOGGER_ERROR(logger, "Failed to get CQ event");
        throw std::runtime_error("Failed to get CQ event");
    }
    SPDLOG_LOGGER_DEBUG(logger, "Processed {} completions", completions.size());
    return completions;
}

__attribute__((always_inline)) 
void* 
RDMAManager::get_recv_addr(uint8_t id) {
    auto it = _id_2_engines.find(id);
    if (unlikely(it == _id_2_engines.end())) {
        SPDLOG_LOGGER_ERROR(logger, "Engine ID {} not found", id);
        throw std::runtime_error("Engine ID not found");
    }
    return it->second->get_recv_addr();
}

__attribute__((always_inline)) 
void 
RDMAManager::add_old_flow_data(uint8_t id, std::vector<MiresgaOFTEntry_t>& data_vec) {
    auto it = _id_2_engines.find(id);
    if (unlikely(it == _id_2_engines.end())) {
        SPDLOG_LOGGER_ERROR(logger, "Engine ID {} not found", id);
        throw std::runtime_error("Engine ID not found");
    }
    it->second->add_flow_data(data_vec);
}

__attribute__((always_inline))
void 
RDMAManager::add_flow_data(MiresgaFlowData_t* flow_data) {
    SPDLOG_LOGGER_INFO(logger, "Adding flow data to RDMA Manager");
    uint8_t crc = flow_data->entry_data.key.crc;
    auto crc_it = _crc_2_id.find(crc);
    if (crc_it == _crc_2_id.end()) {
        SPDLOG_LOGGER_ERROR(logger, "No RDMA engine handles CRC {:02x}", crc);
        throw std::runtime_error("No RDMA engine handles this CRC");
    }
    uint8_t id = crc_it->second;
    auto it = _id_2_engines.find(id);
    if (unlikely(it == _id_2_engines.end())) {
        SPDLOG_LOGGER_ERROR(logger, "Engine ID {} not found", id);
        throw std::runtime_error("Engine ID not found");
    }
    it->second->add_flow_data(flow_data);
}

__attribute__((always_inline))
void
RDMAManager::del_flow_data(MiresgaFlowData_t* flow_data) {
    uint8_t crc = flow_data->entry_data.key.crc;
    auto crc_it = _crc_2_id.find(crc);
    if (crc_it == _crc_2_id.end()) {
        SPDLOG_LOGGER_ERROR(logger, "No RDMA engine handles CRC {:02x}", crc);
        throw std::runtime_error("No RDMA engine handles this CRC");
    }
    uint8_t id = crc_it->second;
    auto it = _id_2_engines.find(id);
    if (unlikely(it == _id_2_engines.end())) {
        SPDLOG_LOGGER_ERROR(logger, "Engine ID {} not found", id);
        throw std::runtime_error("Engine ID not found");
    }
    it->second->del_flow_data(flow_data);
}