#ifndef MIRESGA_CONFIG_H_
#define MIRESGA_CONFIG_H_

#define DEFAULT_CONFIG_PATH      "../config/config.json"
#define DEFAULT_DPDK_CONFIG_PATH "../config/dpdk.json"
#define ENTRY_BATCH_SIZE 40
#define QUEUE_THRESHOLD  20
#define RDMA_SEND_ADD_BUFFER_SIZE    (65536 * 10)
#define RDMA_SEND_DEL_BUFFER_SIZE    (65536 * 8)
#define RDMA_RECV_BUFFER_SIZE        (RDMA_SEND_ADD_BUFFER_SIZE + \ 
                                      RDMA_SEND_DEL_BUFFER_SIZE)
#define MAX_CQ_SIZE           16
#define CQ_PRESENTER          0x0a0a0a0a
#define DEFAULT_FLOW_MAP_SIZE 65536

#endif