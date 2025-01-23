#ifndef ENTRY_CONTROLLER_HPP_
#define ENTRY_CONTROLLER_HPP_

#include "my_config.hpp"
#include "flow_data.hpp"
#include "concurrentqueue/concurrentqueue.h"
#include <thread>
#include <memory>
#include <iostream>
#include <vector>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/socket.h>
#include <unistd.h>
#include <memory.h>


#define BATCH_SIZE 40
#define THRESHOLD  20

class entry_controller_t {
private:
    bool exit_flag;
    my_pair_t * add_pairs;
    my_key_t * del_keys;
    int remain_add_size;
    int remain_del_size;
    moodycamel::ConsumerToken add_token;
    moodycamel::ConsumerToken del_token;
    moodycamel::ConcurrentQueue<my_pair_t> *add_queue;
    moodycamel::ConcurrentQueue<my_key_t> *del_queue;
public:
    status_t status;
    entry_controller_t() = delete;
    entry_controller_t(const entry_controller_t& entry_controller) = delete;
    entry_controller_t(moodycamel::ConcurrentQueue<my_pair_t> *add_queue, 
                       moodycamel::ConcurrentQueue<my_key_t> *del_queue);
    ~entry_controller_t();
    ssize_t get_offloaded_entries(char *send_buffer);
};

#endif