project('pkt_processor', 'cpp', version: '1.0.0',
        default_options: [ 'cpp_std=c++17', 'optimization=3', 'warning_level=3'])
cmake = import('cmake')
libcuckoo_pro = cmake.subproject('third_party/libcuckoo')
libcuckoo_dep = libcuckoo_pro.dependency('libcuckoo')
pkt_processor_inc = include_directories(['.', '../..', '../third_party'])
rule_controller_pro = subproject('rule_controller')
rule_controller_dep = rule_controller_pro.get_variable('rule_controller_dep')
dpdk_dep = dependency('libdpdk', required: true)
threads_dep = dependency('threads', required: true)


pkt_processor_lib = shared_library('pkt_processor', 'pkt_processor.cpp', 
                                   install: true,
                                   dependencies: [libcuckoo_dep, rule_controller_dep,  
                                                  dpdk_dep, threads_dep], 
                                   include_directories: pkt_processor_inc)
pkt_processor_dep = declare_dependency(link_with: pkt_processor_lib, 
                                       include_directories: pkt_processor_inc)