#include "operation_queue.h"

static auto logger = spdlog::stdout_color_mt("OperationQueue");

OperationQueue::OperationQueue() :  
    _max_queue_size(1024 * 1024) {
    _operation_count = 0;
    _operation_queue = new Operation_t[_max_queue_size];
    _key_to_index.reserve(_max_queue_size);
}

OperationQueue::~OperationQueue() {
    delete[] _operation_queue;
    _key_to_index.clear();
}

__attribute__((always_inline))
void
OperationQueue::add_operation(
    Operation_t& operation
) {
    std::shared_lock lock(_mutex);
    uint64_t key = packed_key(operation.entry.key);
    ssize_t idx = -1;
    _key_to_index.visit(key, [&idx](const auto& item){
        idx = item.second;
    });
    if (idx == -1) {
        idx = _operation_count.fetch_add(1, std::memory_order_relaxed);
        _key_to_index.emplace(key, idx);
    }
    SPDLOG_LOGGER_DEBUG(logger, "Trying to add operation: type={}, idx = {}", static_cast<int>(operation.type), idx);
    if (idx >= _max_queue_size) {
        SPDLOG_LOGGER_WARN(logger, "Operation queue is full");
        _operation_count.fetch_sub(1, std::memory_order_relaxed);
        return;
    }
    _operation_queue[idx] = operation;
    SPDLOG_LOGGER_DEBUG(logger, "Added operation: type={}, idx = {}", static_cast<int>(operation.type), idx);
}

__attribute__((always_inline))
void
OperationQueue::add_old_entries(
    std::vector<MiresgaOFTEntry_t>& entries
) {
    for (auto& entry : entries) {
        Operation_t op;
        op.type = INSERT;
        op.entry = entry;
        add_operation(op);
    }
}

__attribute__((always_inline))
ssize_t
OperationQueue::get_all_operations(void* buffer) {
    std::unique_lock lock(_mutex);
    ssize_t count = _operation_count.load();
    if (count > 0) {
        memcpy(buffer, _operation_queue, count * sizeof(Operation_t));
    }
    _key_to_index.clear();
    _operation_count.store(0);
    return count;
}