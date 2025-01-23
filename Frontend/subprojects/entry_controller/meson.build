project('entry_controller', 'cpp', version:'1.0.0', 
        default_options: [ 'optimization=3', 'warning_level=3'])

pthread_dep = dependency('threads')
dpdk_dep = dependency('libdpdk', required: true)
entry_controller_inc = include_directories(['.', '../..', '../third_party'])
entry_controller_lib = shared_library('entry_controller', 'entry_controller.cpp', install:true, 
                                      dependencies: [pthread_dep, dpdk_dep],
                                      include_directories: entry_controller_inc)
entry_controller_dep = declare_dependency(link_with: entry_controller_lib, 
                                          include_directories: entry_controller_inc)