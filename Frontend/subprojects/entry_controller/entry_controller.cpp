#include "entry_controller.hpp"

using std::thread;

entry_controller_t::entry_controller_t(moodycamel::ConcurrentQueue<my_pair_t> *add_queue, 
                                       moodycamel::ConcurrentQueue<my_key_t> *del_queue):add_token(*add_queue), del_token(*del_queue) {
    add_pairs = NULL;
    del_keys = NULL;
    status = status_t::INTERNAL_ERROR;
    remain_add_size = 0;
    remain_del_size = 0;
    exit_flag = true;
    this->add_queue = add_queue;
    this->del_queue = del_queue;
    add_pairs = new my_pair_t [BATCH_SIZE * 2];
    del_keys = new my_key_t [BATCH_SIZE * 2];
    if(add_pairs == nullptr || del_keys == nullptr) {
        perror("[ERROR]: malloc in entry_controller");
        return;
    }
    status = OK;
}

entry_controller_t::~entry_controller_t() {
    // if(sock != -1) {
    //     close(sock);
    // }
    if(add_pairs) {
        delete [] add_pairs;
    }
    if(del_keys) {
        delete [] del_keys;
    }
}

ssize_t entry_controller_t::get_offloaded_entries(char *send_buffer) {
    size_t add_size = 0, del_size = 0;
    ssize_t now_bytes = -1;
    if(remain_add_size <= THRESHOLD && remain_del_size <= THRESHOLD) {
        add_size = add_queue->try_dequeue_bulk(add_token, add_pairs + remain_add_size, BATCH_SIZE);
        del_size = del_queue->try_dequeue_bulk(del_token, del_keys + remain_del_size, BATCH_SIZE);
        remain_add_size += add_size;
        remain_del_size += del_size;
    }
    if(remain_add_size == 0 && remain_del_size == 0) {
        return 0;
    }
    now_bytes = 0;
    uint8_t msg_type = operation_type_t::OFFLOAD_ENTRIES;
    memcpy(send_buffer + now_bytes, &msg_type, sizeof(uint8_t));
    now_bytes += sizeof(uint8_t);
    uint8_t need_add_size = (remain_add_size > BATCH_SIZE) ? BATCH_SIZE : remain_add_size;
    send_buffer[now_bytes] = need_add_size;
    now_bytes += sizeof(uint8_t);
    uint8_t need_del_size = (remain_del_size > BATCH_SIZE) ? BATCH_SIZE : remain_del_size;
    send_buffer[now_bytes] = need_del_size;
    now_bytes += sizeof(uint8_t);
    memcpy(send_buffer + now_bytes, add_pairs, sizeof(my_pair_t) * need_add_size);
    now_bytes += sizeof(my_pair_t) * need_add_size;
    memcpy(send_buffer + now_bytes, del_keys, sizeof(my_key_t) * need_del_size);
    now_bytes += sizeof(my_key_t) * need_del_size;

    if(need_add_size < remain_add_size) {
        memcpy(add_pairs, add_pairs + need_add_size, sizeof(my_hash_pair_t) * (remain_add_size - need_add_size));
    }
    if(need_del_size < remain_del_size) {
        memcpy(del_keys, del_keys + need_del_size, sizeof(my_key_t) * (remain_del_size - need_del_size));
    }
    remain_add_size -= need_add_size;
    remain_del_size -= need_del_size;
    return now_bytes;
}