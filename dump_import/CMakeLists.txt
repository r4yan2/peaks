cmake_minimum_required(VERSION 3.9)
project(dump_import)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-march=native -Wall -static-libgcc -lstdc++ -pipe")

add_definitions(-DGPG_COMPATIBLE)
add_definitions(-DTMP_FOLDER_CSV="/tmp/dump_import/")
add_definitions(-DERROR_FOLDER="/tmp/gpg_keyserver_ERRORS/dump_import_errors/")
add_definitions(-DDEFAULT_DUMP_PATH="/tmp/pgp_dump/")

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g3 -O0 -pg")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3 -Werror")

set(SOURCE_FILES dump_import.cc DBManager.cc Thread_Pool.cc unpacker.cc DBStruct.h utils.cc Key_Tools.cc)
add_library(dump_import ${SOURCE_FILES})

target_link_libraries(dump_import ${OpenPGP_DIRECTORY}/libOpenPGP.a)
target_link_libraries(dump_import gmp)
target_link_libraries(dump_import bz2)
target_link_libraries(dump_import mysqlcppconn)
target_link_libraries(dump_import z)
target_link_libraries(dump_import ${Boost_LIBRARIES})
target_link_libraries(dump_import ${CMAKE_THREAD_LIBS_INIT})
