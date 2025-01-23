#include "controller.h"

static int server_fd, epoll_fd;
static struct rule_t rules[256];
static size_t rule_size, d_index_size;
static struct d_index_t d_index_table[256];
static struct server_info_t v_info;

void init_controller(char *ip, uint16_t port, char *rule_json_path, 
                     char *d_index_json_path, char *v_info_json_path) {
    // Create a socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket failed");
        exit(1);
    }

    // Set up the server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip);
    server_addr.sin_port = htons(port);

    // Bind the socket to the server address
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("server bind failed");
        exit(1);
    }

    // Listen for incoming connections
    if (listen(server_fd, SOMAXCONN) == -1) {
        perror("listen failed");
        exit(1);
    }

    // Create an epoll instance
    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1 failed");
        exit(1);
    }

    // Add the server socket to the epoll instance
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) == -1) {
        perror("epoll_ctl failed");
        exit(1);
    }

    // Parse the rule JSON file
    FILE *rule_file = fopen(rule_json_path, "r");
    if (rule_file == NULL) {
        perror("fopen failed");
        exit(1);
    }
    
    fseek(rule_file, 0, SEEK_END);
    long rule_file_size = ftell(rule_file);
    fseek(rule_file, 0, SEEK_SET);
    char *rule_json = (char *)malloc(rule_file_size + 1);
    fread(rule_json, 1, rule_file_size, rule_file);
    fclose(rule_file);
    rule_json[rule_file_size] = '\0';
    
    // Parse the rule JSON using cJSON
    cJSON *rule_array = cJSON_Parse(rule_json);
    if (rule_array == NULL) {
        perror("cJSON_Parse failed");
        exit(1);
    }

    // Iterate through the JSON array and populate the ru


    rule_size = cJSON_GetArraySize(rule_array);
    for (int i = 0; i < rule_size; i++) {
        cJSON *rule_item = cJSON_GetArrayItem(rule_array, i);
        if (rule_item == NULL) {
            perror("cJSON_GetArrayItem failed");
            exit(1);
        }

        cJSON *key = cJSON_GetObjectItem(rule_item, "key");
        cJSON *d_index = cJSON_GetObjectItem(rule_item, "d_index");
        cJSON *offload_flag = cJSON_GetObjectItem(rule_item, "offload_flag");
        strcpy(rules[i].rule, key->valuestring);
        rules[i].d_index = d_index->valueint;
        rules[i].offload_flag = offload_flag->valueint;
    }

    // Free the JSON object
    cJSON_Delete(rule_array);
    free(rule_json);

    // Parse the d_index JSON file
    FILE *d_index_file = fopen(d_index_json_path, "r");
    if (d_index_file == NULL) {
        perror("fopen failed");
        exit(1);
    }
    fseek(d_index_file, 0, SEEK_END);
    long d_index_file_size = ftell(d_index_file);
    fseek(d_index_file, 0, SEEK_SET);
    char *d_index_json = (char *)malloc(d_index_file_size + 1);
    fread(d_index_json, 1, d_index_file_size, d_index_file);
    fclose(d_index_file);
    d_index_json[d_index_file_size] = '\0';

    // Parse the d_index JSON using cJSON
    cJSON *d_index_array = cJSON_Parse(d_index_json);
    if (d_index_array == NULL) {
        perror("cJSON_Parse failed");
        exit(1);
    }

    // Iterate through the JSON array and populate the d_index table

    d_index_size = cJSON_GetArraySize(d_index_array);
    for (int i = 0; i < d_index_size; i++) {
        cJSON *d_index_item = cJSON_GetArrayItem(d_index_array, i);
        if (d_index_item == NULL) {
            perror("cJSON_GetArrayItem failed");
            exit(1);
        }

        cJSON *d_index = cJSON_GetObjectItem(d_index_item, "d_index");
        cJSON *ip = cJSON_GetObjectItem(d_index_item, "ip");
        cJSON *port = cJSON_GetObjectItem(d_index_item, "port");

        d_index_table[i].d_index = d_index->valueint;
        d_index_table[i].server_info.ip = ip->valueint;
        d_index_table[i].server_info.port = port->valueint;
        cJSON *mac_array = cJSON_GetObjectItem(d_index_item, "mac_array");
        for(int j = 0; j < 6; ++j) {
            d_index_table[i].server_info.mac[j] = cJSON_GetArrayItem(mac_array, j)->valueint;
        }
    }

    // Free the JSON object
    cJSON_Delete(d_index_array);
    free(d_index_json);

    // Parse the v_info JSON file
    FILE *v_info_file = fopen(v_info_json_path, "r");
    if (v_info_file == NULL) {
        perror("fopen failed");
        exit(1);
    }
    fseek(v_info_file, 0, SEEK_END);
    long v_info_file_size = ftell(v_info_file);
    fseek(v_info_file, 0, SEEK_SET);
    char *v_info_json = (char *)malloc(v_info_file_size + 1);
    fread(v_info_json, 1, v_info_file_size, v_info_file);
    fclose(v_info_file);
    v_info_json[v_info_file_size] = '\0';

    // Parse the v_info JSON using cJSON
    cJSON *v_info_obj = cJSON_Parse(v_info_json);
    if (v_info_obj == NULL) {
        perror("cJSON_Parse failed");
        exit(1);
    }

    v_info.ip = cJSON_GetObjectItem(v_info_obj, "ip")->valueint;
    v_info.port = cJSON_GetObjectItem(v_info_obj, "port")->valueint;
    cJSON *mac_array = cJSON_GetObjectItem(v_info_obj, "mac_array");
    for(int i = 0; i < 6; ++i) {
        v_info.mac[i] = cJSON_GetArrayItem(mac_array, i)->valueint;
    }

    // Free the JSON object
    cJSON_Delete(v_info_obj);
    free(v_info_json);
}


void run_controller() {
    char recv_buffer[1024], send_buffer[1024];
    offload_connection_table_entry_t offload_connection_table_entry[256];
    struct epoll_event events[10];
    while(true) {
        int entry_index = 0;
        int event_count = epoll_wait(epoll_fd, events, 10, -1);
        if (event_count == -1) {
            perror("epoll_wait failed");
            exit(1);
        }
        for (int i = 0; i < event_count; i++) {
            if (events[i].data.fd == server_fd) {
                int client_fd = accept(server_fd, NULL, NULL);
                if (client_fd == -1) {
                    perror("accept failed");
                    exit(1);
                }
                printf("New connection.\n");
                int flag = 1;
                if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&flag, sizeof(int)) < 0) {
                    perror("setsockopt");
                    exit(EXIT_FAILURE);
                }

                struct epoll_event event;
                event.events = EPOLLIN;
                event.data.fd = client_fd;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) == -1) {
                    perror("epoll_ctl failed");
                    exit(1);
                }
                send_buffer[0] = 0;
                send_buffer[1] = rule_size;
                send_buffer[2] = 0;
                size_t now_bytes = 3;
                for(int i = 0; i < rule_size; ++i) {
                    strcpy(send_buffer + now_bytes, rules[i].rule);
                    now_bytes += strlen(rules[i].rule);
                    send_buffer[now_bytes] = '\0';
                    now_bytes++;
                    send_buffer[now_bytes] = rules[i].d_index;
                    now_bytes++;
                    send_buffer[now_bytes] = rules[i].offload_flag;
                    now_bytes++;
                }
                if(send(client_fd, send_buffer, now_bytes, 0) < 0) {
                    perror("send failed");
                    exit(1);
                }
                send_buffer[0] = 1;
                send_buffer[1] = d_index_size;
                send_buffer[2] = 0;
                now_bytes = 3;
                for(int i = 0; i < d_index_size; ++i) {
                    send_buffer[now_bytes] = d_index_table[i].d_index;
                    now_bytes++;
                    memcpy(send_buffer + now_bytes, &d_index_table[i].server_info, sizeof(struct server_info_t));
                    now_bytes += sizeof(struct server_info_t);
                }
                if(send(client_fd, send_buffer, now_bytes, 0) < 0) {
                    perror("send failed");
                    exit(1);
                }
                sleep(1); // Otherwise the two packet will be 
                send_buffer[0] = 2;
                now_bytes = 1;
                memcpy(send_buffer + now_bytes, &v_info, sizeof(struct server_info_t));
                now_bytes += sizeof(struct server_info_t);
                memset(send_buffer + now_bytes, 0, 3);
                now_bytes += 3;
                if(send(client_fd, send_buffer, now_bytes, 0) < 0) {
                    perror("send failed");
                    exit(1);
                }
            } else {
                int client_fd = events[i].data.fd;
                ssize_t recv_size = recv(client_fd, recv_buffer, 1024, 0);
                if (recv_size == -1) {
                    perror("recv failed");
                    exit(1);
                }

                if (recv_size == 0) {
                    close(client_fd);
                    continue;
                }
                ssize_t now_bytes = 0;
                if(bf_rt_begin_batch(session) != BF_SUCCESS) {
                    printf("Fail to start batch.\n");
                    continue;
                }
                while(now_bytes  <= recv_size) {
                    if(recv_buffer[now_bytes] == 3) {
                        // printf("Offload_entries\n");
                        // struct timeval start, end;
                        // long seconds, useconds;
                        // double mtime;
                        // gettimeofday(&start, NULL);
                        now_bytes++;
                        uint8_t add_size = recv_buffer[now_bytes];
                        now_bytes++;
                        uint8_t del_size = recv_buffer[now_bytes];
                        now_bytes++;
                        // printf("Add_size: %d, Del_size: %d\n", add_size, del_size);
                        // gettimeofday(&end, NULL);
                        // seconds  = end.tv_sec  - start.tv_sec;
                        // useconds = end.tv_usec - start.tv_usec;
                        // mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;

                        // printf("%f\n", mtime);
                        for(int i = 0; i < add_size; ++i) {
                            struct my_pair_t *pair = (struct my_pair_t *)(recv_buffer + now_bytes);
                            // printf("Cip: %u, Cport: %d, d_index: %d\n", pair->key.client_ip, pair->key.client_port, pair->data.d_index);
                            bf_rt_key_field_set_value(offload_connection_table_info.key_hdl[entry_index], 
                                                      offload_connection_table_info.kid_cip, 
                                                      pair->key.client_ip);
    
                            bf_rt_key_field_set_value(offload_connection_table_info.key_hdl[entry_index],
                                                      offload_connection_table_info.kid_cport,
                                                      pair->key.client_port);
                            bf_rt_data_field_set_value(offload_connection_table_info.data_hdl[entry_index],
                                                       offload_connection_table_info.did_d_index,
                                                       pair->data.d_index);
                            if(bf_rt_table_entry_add(offload_connection_table_info.table_hdl, 
                                                     session,
                                                     dev_tgt,
                                                     offload_connection_table_info.key_hdl[entry_index], 
                                                     offload_connection_table_info.data_hdl[entry_index]) != BF_SUCCESS) {
                                //printf("Failed to add entry.\n");
                            }
                            entry_index++;
                            now_bytes += sizeof(struct my_pair_t);
                        }
                        for(int i = 0; i < del_size; ++i) {
                            struct my_key_t *key = (struct my_key_t *)(recv_buffer + now_bytes);
                            bf_rt_key_field_set_value(offload_connection_table_info.key_hdl[entry_index], 
                                                            offload_connection_table_info.kid_cip, 
                                                            key->client_ip);
                            bf_rt_key_field_set_value(offload_connection_table_info.key_hdl[entry_index],
                                                            offload_connection_table_info.kid_cport,
                                                            key->client_port);
                            if(bf_rt_table_entry_del(offload_connection_table_info.table_hdl,
                                                     session,
                                                     dev_tgt,
                                                     offload_connection_table_info.key_hdl[entry_index]) != BF_SUCCESS) {
                                //printf("Failed to del entry\n");
                            }
                            entry_index++;
                            now_bytes += sizeof(struct my_key_t);
                        }
                    }
                    else {
                        break;
                    }
                }
                if(bf_rt_end_batch(session, true) != BF_SUCCESS) {
                    printf("Fail to end batch.\n");
                }
            }
        }
    }
}