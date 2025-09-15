cmake_minimum_required(VERSION 3.8)
project(MiresgaSwitchControlPlane VERSION 2.0.0 LANGUAGES CXX)
set(PROJECT_VERSION_RC "rc1")
set(CMAKE_CXX_STANDARD 17)

option(FMT_DOC "Build and install documentation" OFF)
option(FMT_TEST "Build and install tests" OFF)
option(FMT_INSTALL "Generate the install target" OFF)
option(SPDLOG_BUILD_TESTS "Build spdlog tests" OFF)
option(SPDLOG_BUILD_EXAMPLE "Build spdlog example" OFF)
option(SPDLOG_INSTALL "Generate the install target" OFF)
option(SPDLOG_FMT_EXTERNAL "Use external fmt library" ON)
option(SPDLOG_COMPILED_LIB "Build spdlog as a compiled library" ON)
add_subdirectory(third_party/json)
add_subdirectory(third_party/fmt)
add_subdirectory(third_party/spdlog)

find_package(Threads REQUIRED)
find_library(DRIVER_LIBRARY driver REQUIRED PATHS $ENV{SDE_INSTALL}/lib)
find_library(BFSYS_LIBRARY bfsys REQUIRED PATHS $ENV{SDE_INSTALL}/lib)
find_library(BFUTILS_LIBRARY bfutils REQUIRED PATHS $ENV{SDE_INSTALL}/lib)
find_library(BF_SWITCHD_LIB_LIBRARY bf_switchd_lib REQUIRED PATHS $ENV{SDE_INSTALL}/lib)

file(GLOB SOURCES src/*.cpp)
set(INCLUDE_DIRECTORIES include)
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE
    nlohmann_json::nlohmann_json
    Threads::Threads
    spdlog::spdlog
    fmt::fmt
    ${DRIVER_LIBRARY}
    ${BFSYS_LIBRARY}
    ${BFUTILS_LIBRARY}
    ${BF_SWITCHD_LIB_LIBRARY}
)

target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_DIRECTORIES} $ENV{SDE_INSTALL}/include)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Debug build")
    target_compile_definitions(${PROJECT_NAME} PRIVATE SPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_DEBUG DEBUG=1)
    target_compile_options(${PROJECT_NAME} PRIVATE -g)
else()
    message(STATUS "Release build")
    target_compile_definitions(${PROJECT_NAME} PRIVATE SPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_INFO NDEBUG=1)
    target_compile_options(${PROJECT_NAME} PRIVATE -O3 -march=native)
endif()