cmake_minimum_required(VERSION 3.5.1)
project(recon_daemon)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-march=native -DGPG_COMPATIBLE -Wall -static-libgcc -lstdc++ -pipe ")
add_definitions(-DGPG_COMPATIBLE)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g3 -O0 -pg")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3 -Werror")

set(SOURCE_FILES peer.cc recon_manager.cc Connection_Manager.cc Message.cc Buffer.cc Bitset.cc logger.cc exception.cc myset.cc pTreeDB.cc RECON_DBManager.cc DB_info.h Utils.cc DBStruct.h)

add_library(recon_daemon ${SOURCE_FILES})

set(OpenPGP_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../OpenPGP)
set(NTL_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../lib/ntl)
set(GMP_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../lib/gmp)
set(DUMP_IMPORT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../dump_import)

target_link_libraries(recon_daemon mysqlcppconn)
target_link_libraries(recon_daemon gmp)
target_link_libraries(recon_daemon curl)
target_link_libraries(recon_daemon ${NTL_DIRECTORY}/lib/libntl.a)
target_link_libraries(recon_daemon ${GMP_DIRECTORY}/lib/libgmp.so)
target_link_libraries(recon_daemon dump_import)

include_directories(${OpenPGP_DIRECTORY})
include_directories(${DUMP_IMPORT_DIRECTORY})
include_directories(${GMP_DIRECTORY}/include)
include_directories(${NTL_DIRECTORY}/include)
