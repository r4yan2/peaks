cmake_minimum_required(VERSION 3.5.1)
project(import)

set(SOURCE_FILES import.cc DBManager.cc unpacker.cc DBStruct.h Key_Tools.cc)
add_library(import ${SOURCE_FILES})
find_package(Boost REQUIRED system filesystem)


target_link_libraries(import gmp)
target_link_libraries(import bz2)
target_link_libraries(import mysqlcppconn)
target_link_libraries(import z)
target_link_libraries(import ${Boost_LIBRARIES})
target_link_libraries(import ${CMAKE_THREAD_LIBS_INIT})
