cmake_minimum_required(VERSION 3.15)
project(MiresgaSwitchControlPlane VERSION 2.0.0 LANGUAGES CXX)

add_subdirectory(third_party/cJSON)
add_subdirectory(third_party/Collections-C)
find_library(DRIVER_LIBRARY driver REQUIRED)
find_library(BFSYS_LIBRARY bfsys REQUIRED)
find_library(BFUTILS_LIBRARY bfutils REQUIRED)
find_library(BF_SWITCHD_LIB_LIBRARY bf_switchd_lib REQUIRED)
file(GLOB SOURCES src/*.cpp)
set(INCLUDE_DIRECTORIES include)
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE
    cjson::cjson
    collectc::collectc
    ${DRIVER_LIBRARY}
    ${BFSYS_LIBRARY}
    ${BFUTILS_LIBRARY}
    ${BF_SWITCHD_LIB_LIBRARY}
)