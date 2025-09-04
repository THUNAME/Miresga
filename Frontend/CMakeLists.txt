cmake_minimum_required(VERSION 3.14)

project(MiresgaFrontend VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
find_package(Boost REQUIRED)
find_package(PkgConfig REQUIRED)
find_library(NUMA_LIBRARY numa REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)
pkg_check_modules(RDMA REQUIRED libibverbs)

add_subdirectory(third_party/concurrentqueue)
add_subdirectory(third_party/json)
file(GLOB SOURCES src/*.cpp)
set(INCLUDE_DIRECTORIES include ${DPDK_INCLUDE_DIRS} ${RDMA_INCLUDE_DIRS} ${NUMA_INCLUDE_DIR})
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE
    concurrentqueue
    nlohmann_json::nlohmann_json
    Threads::Threads
    Boost::boost
    ${DPDK_LDFLAGS}
    ${RDMA_LDFLAGS}
    ${NUMA_LIBRARY}
)
target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_DIRECTORIES})
