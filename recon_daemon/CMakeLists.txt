cmake_minimum_required(VERSION 3.5.1)
project(recon_daemon)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-march=native -DGPG_COMPATIBLE -Wall -lbz2 -lgmp -lz \
-lmysqlcppconn -static-libgcc -pthread -lstdc++ -pipe -I /home/ray/Projects/peaks/Peaks_Code_test/lib/ntl/include -I ../lib/gmp/include -I ../boost_1_63_0/")
add_definitions(-DGPG_COMPATIBLE)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3 -Werror")

set(SOURCE_FILES pTree.cc pTreeDB.cc DBManager.cc DB_info.h Utils.cc DBStruct.h PTree_settings.h)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
add_executable(recon_daemon ${SOURCE_FILES})

set(OpenPGP_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../OpenPGP)

target_link_libraries(recon_daemon mysqlcppconn)
target_link_libraries(recon_daemon gmp)
target_link_libraries(recon_daemon bz2)
target_link_libraries(recon_daemon z)
target_link_libraries(recon_daemon ${CMAKE_CURRENT_SOURCE_DIR}/../lib/ntl/lib/libntl.a)
include_directories(dump_import PRIVATE ${OpenPGP_DIRECTORY})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../boost_1_63_0)
include_directories(../lib/gmp/include)
link_directories(../lib/gmp/lib)
 
target_link_libraries(recon_daemon gmp)
