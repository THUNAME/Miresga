#include "entry_manager.h"

static auto logger = spdlog::stdout_color_mt("entry_manager");

EntryManager::EntryManager(): _add_token(_add_queue), _del_token(_del_queue)
{
    _remain_entries = new MiresgaOFTEntry_t[ENTRY_BATCH_SIZE * 2]; // * 2 for avoid potential overflow
    _num_remain_entry = 0;
    _remain_keys = new MiresgaOFTKey_t[ENTRY_BATCH_SIZE * 2];
    _num_remain_key = 0;
}

EntryManager::~EntryManager()
{
    delete[] _remain_entries;
    delete[] _remain_keys;
}

EntryManager* EntryManager::get_instance()
{
    if (_instance == nullptr) {
        SPDLOG_LOGGER_INFO(logger, "Creating EntryManager instance");
        _instance = new EntryManager();
    }
    return _instance;
}

void EntryManager::destroy_instance()
{
    if (_instance != nullptr) {
        SPDLOG_LOGGER_WARN(logger, "Destroying EntryManager instance");
        delete _instance;
        _instance = nullptr;
    }
}

void EntryManager::add_entry(moodycamel::ProducerToken& token, MiresgaOFTEntry_t entry)
{
    #ifdef DEBUG
    char ip_str[INET_ADDRSTRLEN];
    SPDLOG_LOGGER_DEBUG(logger, "Adding entry: key({}:{}, {}), data({}, {})", 
                        inet_ntop(AF_INET, &entry.key.client_ip, ip_str, INET_ADDRSTRLEN), entry.key.client_port, 
                        static_cast<int>(entry.key.crc),
                        static_cast<int>(entry.data.flow_state), 
                        static_cast<int>(entry.data.d_index));
    #endif
    _add_queue.enqueue(token, entry);
}

void EntryManager::del_entry(moodycamel::ProducerToken& token, MiresgaOFTKey_t key)
{
    #ifdef DEBUG
    char ip_str[INET_ADDRSTRLEN];
    SPDLOG_LOGGER_DEBUG(logger, "Deleting entry: key({}:{}, {})", 
                        inet_ntop(AF_INET, &key.client_ip, ip_str, INET_ADDRSTRLEN), key.client_port, 
                        static_cast<int>(key.crc));
    #endif
    _del_queue.enqueue(token, key);
}

ssize_t EntryManager::serialize_msg(char* send_buffer)
{
    if (_num_remain_entry <= QUEUE_THRESHOLD && _num_remain_key <= QUEUE_THRESHOLD) {
        _num_remain_entry += _add_queue.try_dequeue_bulk(_add_token, _remain_entries + 
                                                         _num_remain_entry, ENTRY_BATCH_SIZE);
        _num_remain_key += _del_queue.try_dequeue_bulk(_del_token, _remain_keys + 
                                                       _num_remain_key, ENTRY_BATCH_SIZE);
    }
    if (_num_remain_entry == 0 && _num_remain_key == 0) {
        return 0;
    }
    ssize_t total_bytes = 0;
    uint8_t msg_type = static_cast<uint8_t>(OperationType_t::OFFLOAD_ENTRIES);
    memcpy(send_buffer + total_bytes, &msg_type, sizeof(uint8_t));
    total_bytes++;
    uint8_t need_add_size = (_num_remain_entry > ENTRY_BATCH_SIZE) ? 
                            ENTRY_BATCH_SIZE : _num_remain_entry;
    send_buffer[total_bytes] = need_add_size;
    total_bytes++;
    memcpy(send_buffer + total_bytes, _remain_entries, 
           need_add_size * sizeof(MiresgaOFTEntry_t));
    total_bytes += need_add_size * sizeof(MiresgaOFTEntry_t);
    uint8_t need_del_size = (_num_remain_key > ENTRY_BATCH_SIZE) ? 
                            ENTRY_BATCH_SIZE : _num_remain_key;
    send_buffer[total_bytes] = need_del_size;
    total_bytes++;
    memcpy(send_buffer + total_bytes, _remain_keys, 
           need_del_size * sizeof(MiresgaOFTKey_t));
    total_bytes += need_del_size * sizeof(MiresgaOFTKey_t);
    if (need_add_size < _num_remain_entry) {
        memcpy(_remain_entries, _remain_entries + need_add_size, 
                (_num_remain_entry - need_add_size) * sizeof(MiresgaOFTEntry_t));
    }
    if (need_del_size < _num_remain_key) {
        memcpy(_remain_keys, _remain_keys + need_del_size, 
                (_num_remain_key - need_del_size) * sizeof(MiresgaOFTKey_t));
    }
    _num_remain_entry -= need_add_size;
    _num_remain_key -= need_del_size;
    SPDLOG_LOGGER_DEBUG(logger, "Add {} entries, del {} entries, total {} bytes", 
                        need_add_size, need_del_size, total_bytes);
    SPDLOG_LOGGER_DEBUG(logger, "Remain {} entries, {} keys", 
                        _num_remain_entry, _num_remain_key);    
    return total_bytes;
}

moodycamel::ProducerToken& EntryManager::get_add_queue_token() {
    _producer_tokens.emplace_back(moodycamel::ProducerToken(_add_queue));
    return _producer_tokens.back();
}

moodycamel::ProducerToken& EntryManager::get_del_queue_token() {
    _key_producer_tokens.emplace_back(moodycamel::ProducerToken(_del_queue));
    return _key_producer_tokens.back();
}