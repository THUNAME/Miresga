project('rule_controller', 'cpp', version: '1.0.0', 
        default_options: [ 'cpp_std=c++17', 'optimization=3', 'warning_level=3'])

rule_controller_inc = include_directories(['.', '../..'])
dpdk_dep = dependency('libdpdk', required: true)
rule_controller_lib = shared_library('rule_controller', 'rule_controller.cpp', install: true, 
                                     include_directories: rule_controller_inc, dependencies: [dpdk_dep])

rule_controller_dep = declare_dependency(link_with: rule_controller_lib, 
                                         include_directories: rule_controller_inc)