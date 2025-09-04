#include "rdma_manager.h"

RDMAManager::RDMAManager(const char* dev_name, int epoll_fd)
{
    struct ibv_device** dev_list = ibv_get_device_list(NULL);
    if (!dev_list) {
        throw std::runtime_error("Failed to get IB devices list");
    }

    struct ibv_device* ib_dev = nullptr;
    for (int i = 0; dev_list[i]; ++i) {
        if (!strcmp(ibv_get_device_name(dev_list[i]), dev_name)) {
            ib_dev = dev_list[i];
            break;
        }
    }
    if (!ib_dev) {
        ibv_free_device_list(dev_list);
        throw std::runtime_error("IB device not found");
    }

    _ctx = ibv_open_device(ib_dev);
    ibv_free_device_list(dev_list);
    if (!_ctx) {
        throw std::runtime_error("Failed to open IB device");
    }

    _pd = ibv_alloc_pd(_ctx);
    if (!_pd) {
        ibv_close_device(_ctx);
        throw std::runtime_error("Failed to allocate Protection Domain");
    }

    if (ibv_query_gid(_ctx, 0, 0, &_local_gid)) {
        ibv_dealloc_pd(_pd);
        ibv_close_device(_ctx);
        throw std::runtime_error("Failed to get local GID");
    }

    _comp_channel = ibv_create_comp_channel(_ctx);
    if (!_comp_channel) {
        ibv_dealloc_pd(_pd);
        ibv_close_device(_ctx);
        throw std::runtime_error("Failed to create Completion Channel");
    }

    _cq = ibv_create_cq(_ctx, MAX_CQ_SIZE, nullptr, _comp_channel, 0);
    if (!_cq) {
        ibv_destroy_comp_channel(_comp_channel);
        ibv_dealloc_pd(_pd);
        ibv_close_device(_ctx);
        throw std::runtime_error("Failed to create Completion Queue");
    }

    if (ibv_req_notify_cq(_cq, 0)) {
        ibv_destroy_cq(_cq);
        ibv_destroy_comp_channel(_comp_channel);
        ibv_dealloc_pd(_pd);
        ibv_close_device(_ctx);
        throw std::runtime_error("Failed to request CQ notification");
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.u32 = CQ_PRESENTER;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, _comp_channel->fd, &ev) == -1) {
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
        _instance = new RDMAManager(dev_name, epoll_fd);
    }
}

RDMAManager* RDMAManager::get_instance() {
    if (_instance == nullptr) {
        throw std::runtime_error("RDMAManager not initialized");
    }
    return _instance;
}

void RDMAManager::destroy_instance() {
    if (_instance != nullptr) {
        delete _instance;
        _instance = nullptr;
    }
}

char* RDMAManager::add_engine(uint8_t id)
{
    char* msg = new char[1 + sizeof(RDMAInfo_t)];
    msg[0] = static_cast<char>(MiresgaStatus_t::OK);
    RDMAEngine* engine = new RDMAEngine(id, _pd, _cq, _local_gid);
    _id_2_engines[id] = std::make_pair(engine, false);
    return msg;
}

void RDMAManager::update_engine(uint8_t id, RDMAInfo_t* remote_rdma_info)
{
    auto it = _id_2_engines.find(id);
    if (it == _id_2_engines.end()) {
        throw std::runtime_error("Engine ID not found");
    }
    if (it->second.second) {
        throw std::runtime_error("Engine already started");
    }
    it->second.first->init_engine(remote_rdma_info);
}

void RDMAManager::remove_engine(uint8_t id)
{
    auto it = _id_2_engines.find(id);
    if (it == _id_2_engines.end()) {
        throw std::runtime_error("Engine ID not found");
    }
    delete it->second.first;
    _id_2_engines.erase(it);
}

void RDMAManager::start_engine(uint8_t id)
{
    auto it = _id_2_engines.find(id);
    if (it == _id_2_engines.end()) {
        throw std::runtime_error("Engine ID not found");
    }
    it->second.second = true;
}

void RDMAManager::sync_states() {
    for (auto& pair : _id_2_engines) {
        RDMAEngine* engine = pair.second.first;
        if (engine && pair.second.second) {
            engine->sync();
        }
    }
}

void RDMAManager::add_flow_data(MiresgaOFTEntry_t* add_data) {
    uint8_t crc = add_data->key.crc;
    uint8_t id = _crc_2_id[crc];
    _id_2_engines[id].first->add_flow_data(add_data);
}

void RDMAManager::del_flow_data(MiresgaOFTKey_t* del_data) {
    uint8_t crc = del_data->crc;
    uint8_t id = _crc_2_id[crc];
    _id_2_engines[id].first->del_flow_data(del_data);
}

std::vector<ibv_wc> RDMAManager::process_cqe()
{
    std::vector<ibv_wc> completions;
    if(ibv_get_cq_event(_comp_channel, &_cq, nullptr) == 0) {
        ibv_req_notify_cq(_cq, 0);
        int num_wc = 0;
        ibv_wc wc;
        do {
            num_wc = ibv_poll_cq(_cq, 1, &wc);
            if (num_wc > 0) {
                completions.push_back(wc);
            }
        } while(num_wc != 0);
        ibv_ack_cq_events(_cq, 1);
    }
    return completions;
}

void* RDMAManager::get_recv_addr(uint8_t id) {
    auto it = _id_2_engines.find(id);
    if (it == _id_2_engines.end()) {
        throw std::runtime_error("Engine ID not found");
    }
    return it->second.first->get_recv_addr();
}