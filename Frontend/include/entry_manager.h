#ifndef ENTRY_MANAGER_H_
#define ENTRY_MANAGER_H_

#include "fmt/format.h"
#include "fmt/ranges.h"
#include "spdlog/spdlog.h"
#include "miresga_utils.h"
#include "miresga_config.h"
#include "concurrentqueue.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <vector>
#include <arpa/inet.h>

typedef moodycamel::ConcurrentQueue<MiresgaOFTEntry_t> EntryQueue;
typedef moodycamel::ConcurrentQueue<MiresgaOFTKey_t> KeyQueue;

class EntryManager
{
private:
    inline static EntryManager* _instance = nullptr;
    moodycamel::ConsumerToken _add_token;
    moodycamel::ConsumerToken _del_token;
    EntryQueue _add_queue;
    KeyQueue _del_queue;
    MiresgaOFTEntry_t *_remain_entries;
    size_t _num_remain_entry;
    MiresgaOFTKey_t *_remain_keys;
    size_t _num_remain_key;
    std::vector<moodycamel::ProducerToken> _producer_tokens;
    std::vector<moodycamel::ProducerToken> _key_producer_tokens;
    EntryManager();
    ~EntryManager();
public:
    static EntryManager* get_instance();
    static void destroy_instance();
    void add_entry(moodycamel::ProducerToken& token, MiresgaOFTEntry_t entry);
    void del_entry(moodycamel::ProducerToken& token, MiresgaOFTKey_t key);
    moodycamel::ProducerToken* get_add_queue_token();
    moodycamel::ProducerToken* get_del_queue_token();
    ssize_t serialize_msg(char* send_buffer);
};

#endif