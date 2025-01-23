project('L7LB_Server', 'cpp', version: '1.0.0', 
        default_options: [ 'cpp_std=c++17', 'optimization=3', 'warning_level=3'])

cmake = import('cmake')
libcuckoo_pro = cmake.subproject('third_party/libcuckoo')
libcuckoo_dep = libcuckoo_pro.dependency('libcuckoo')
json_pro = subproject('third_party/json')
json_dep = json_pro.get_variable('nlohmann_json_dep')
pthread_dep = dependency('threads')
dpdk_dep = dependency('libdpdk', required: true)
rule_controller_pro = subproject('rule_controller')
rule_controller_dep = rule_controller_pro.get_variable('rule_controller_dep')
entry_controller_pro = subproject('entry_controller')
entry_controller_dep = entry_controller_pro.get_variable('entry_controller_dep')
pkt_processor_pro = subproject('pkt_processor')
pkt_processor_dep = pkt_processor_pro.get_variable('pkt_processor_dep')
cc = meson.get_compiler('cpp')
numa_dep = cc.find_library('numa', required: true)

executable('L7LB_Server', 'main.cpp', 
            dependencies: [libcuckoo_dep, rule_controller_dep,  
                           entry_controller_dep, pkt_processor_dep,
                           pthread_dep, dpdk_dep, json_dep, numa_dep])