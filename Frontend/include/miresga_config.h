#ifndef MIRESGA_CONFIG_H_
#define MIRESGA_CONFIG_H_

#define DEFAULT_CONFIG_PATH      "../config/config.json"
#define DEFAULT_DPDK_CONFIG_PATH "../config/dpdk.json"
#define ENTRY_BATCH_SIZE 40
#define QUEUE_THRESHOLD  20
#define RDMA_BUFFER_SIZE (65536 * 10)
#define MAX_CQ_SIZE           16
#define CQ_PRESENTER          0x0a0a0a0a
#define TIMER_MASK            0xa0a0a000
#define DEFAULT_FLOW_MAP_SIZE 65536

#endif