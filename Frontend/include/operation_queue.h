#ifndef OPERATION_QUEUE_H_
#define OPERATION_QUEUE_H_

#include "fmt/format.h"
#include "fmt/ranges.h"
#include "spdlog/spdlog.h"
#include "miresga_utils.h"
#include "miresga_config.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <atomic>
#include <vector>
#include <shared_mutex>
#include <boost/unordered/concurrent_flat_map.hpp>

enum OperationType_t {
    INSERT,
    DELETE
};

struct Operation_t {
    OperationType_t type;
    MiresgaOFTEntry_t entry;
};

class OperationQueue {
private:
    std::shared_mutex _mutex;
    Operation_t* _operation_queue;
    std::atomic<ssize_t> _operation_count;
    boost::unordered::concurrent_flat_map<uint64_t, ssize_t> _key_to_index;
    ssize_t _max_queue_size;
public:
    OperationQueue();
    ~OperationQueue();
    void add_operation(Operation_t& operation);
    void add_old_entries(std::vector<MiresgaOFTEntry_t>& entries);
    ssize_t get_all_operations(void* buffer);
};


#endif