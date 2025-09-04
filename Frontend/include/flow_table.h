#ifndef FLOW_TABLE_H_
#define FLOW_TABLE_H_

#include "miresga_config.h"
#include "miresga_utils.h"
#include <vector>
#include <boost/unordered/concurrent_flat_map.hpp>

typedef boost::unordered::concurrent_flat_map<uint64_t, MiresgaFlowData_t*> FlowMap_t;

class FlowTable 
{
private:
    inline static FlowTable* _instance = nullptr;
    FlowMap_t _flow_map;
    FlowTable();
    ~FlowTable();
public:
    static FlowTable* get_instance();
    static void destroy_instance();
    void insert_flow(uint64_t key, MiresgaFlowData_t* flow_data);
    MiresgaFlowData_t* get_flow(uint64_t key);
    void remove_flow(uint64_t key);
};

#endif