cmake_minimum_required(VERSION 3.8)
project(unpacker)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-march=native -DGPG_COMPATIBLE -Wall -lbz2 -lgmp -lz \
            -lmysqlcppconn -static-libgcc -pthread -lstdc++ -pipe -lboost_system -lboost_filesystem")
add_definitions(-DGPG_COMPATIBLE)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3 -Werror")

set(SOURCE_FILES main.cc Thread_Pool.cc unpacker.cc DBManager.cc Key_Tools.cc DBStruct.h utils.cc DB_info.h)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
add_executable(unpacker ${SOURCE_FILES})

set(OpenPGP_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../OpenPGP)
include_directories(${OpenPGP_DIRECTORY})
link_directories(${OpenPGP_DIRECTORY})

target_link_libraries(unpacker ${OpenPGP_DIRECTORY}/libOpenPGP.a)
