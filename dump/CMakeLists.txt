cmake_minimum_required(VERSION 3.9)
project(dump)

set(SOURCE_FILES dump.cc DBManager.cc)
add_library(dump ${SOURCE_FILES})
find_package(Boost REQUIRED system filesystem)

target_link_libraries(dump mysqlcppconn)
target_link_libraries(dump ${Boost_LIBRARIES})
target_link_libraries(dump ${CMAKE_THREAD_LIBS_INIT})
