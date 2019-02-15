cmake_minimum_required(VERSION 3.9)
project(dump_import)

set(SOURCE_FILES dump_import.cc DBManager.cc Thread_Pool.cc unpacker.cc DBStruct.h utils.cc Key_Tools.cc)
add_library(dump_import ${SOURCE_FILES})
find_package(Boost REQUIRED system filesystem)

target_link_libraries(dump_import ${OpenPGP_DIRECTORY}/libOpenPGP.a)
target_link_libraries(dump_import gmp)
target_link_libraries(dump_import bz2)
target_link_libraries(dump_import mysqlcppconn)
target_link_libraries(dump_import z)
target_link_libraries(dump_import ${Boost_LIBRARIES})
target_link_libraries(dump_import ${CMAKE_THREAD_LIBS_INIT})
