cmake_minimum_required(VERSION 3.8)
project(MiresgaSwitchControlPlane VERSION 2.0.0 LANGUAGES CXX)
set(PROJECT_VERSION_RC "rc1")
set(CMAKE_CXX_STANDARD 17)
add_subdirectory(third_party/json)
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
    ${DRIVER_LIBRARY}
    ${BFSYS_LIBRARY}
    ${BFUTILS_LIBRARY}
    ${BF_SWITCHD_LIB_LIBRARY}
)

target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_DIRECTORIES} $ENV{SDE_INSTALL}/include)