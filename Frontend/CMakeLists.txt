cmake_minimum_required(VERSION 3.12...3.21)

project(MiresgaFrontend VERSION 2.0.0 LANGUAGES CXX)
set(PROJECT_VERSION_RC "rc1")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(Boost REQUIRED)
find_package(PkgConfig REQUIRED)
find_library(NUMA_LIBRARY numa REQUIRED)
find_library(JEMALLOC_LIB jemalloc QUIET)
pkg_check_modules(DPDK REQUIRED libdpdk)
pkg_check_modules(RDMA REQUIRED libibverbs)


option(FMT_DOC "Build and install documentation" OFF)
option(FMT_TEST "Build and install tests" OFF)
option(FMT_INSTALL "Generate the install target" OFF)
option(SPDLOG_BUILD_TESTS "Build spdlog tests" OFF)
option(SPDLOG_BUILD_EXAMPLE "Build spdlog example" OFF)
option(SPDLOG_INSTALL "Generate the install target" OFF)
option(SPDLOG_FMT_EXTERNAL "Use external fmt library" ON)
option(SPDLOG_COMPILED_LIB "Build spdlog as a compiled library" ON)

add_subdirectory(third_party/fmt)
add_subdirectory(third_party/spdlog)
add_subdirectory(third_party/concurrentqueue)
add_subdirectory(third_party/json)

file(GLOB SOURCES src/*.cpp)
set(INCLUDE_DIRECTORIES include ${DPDK_INCLUDE_DIRS} ${RDMA_INCLUDE_DIRS} ${NUMA_INCLUDE_DIR})

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE
    concurrentqueue
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    Threads::Threads
    Boost::boost
    fmt::fmt
    ${DPDK_LDFLAGS}
    ${RDMA_LDFLAGS}
    ${NUMA_LIBRARY}
)
target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_DIRECTORIES})

if (JEMALLOC_LIB)
    message(STATUS "Using jemalloc")
    target_link_libraries(${PROJECT_NAME} PRIVATE ${JEMALLOC_LIB})
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Debug build")
    target_compile_definitions(${PROJECT_NAME} PRIVATE SPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_DEBUG DEBUG=1)
    target_compile_options(${PROJECT_NAME} PRIVATE -g -Wno-attributes)
else()
    message(STATUS "Release build")
    target_compile_definitions(${PROJECT_NAME} PRIVATE SPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_INFO NDEBUG=1)
    target_compile_options(${PROJECT_NAME} PRIVATE -g -O3 -march=native -flto=4 -Wno-attributes)
endif()