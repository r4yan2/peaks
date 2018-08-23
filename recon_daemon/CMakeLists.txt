cmake_minimum_required(VERSION 3.5.1)
project(recon_daemon)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-march=native -DGPG_COMPATIBLE -Wall -lmysqlcppconn -static-libgcc -pthread -lstdc++ -pipe -lcurl")
add_definitions(-DGPG_COMPATIBLE)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g3 -pg")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3 -Werror")

set(SOURCE_FILES main.cc peer.cc recon_manager.cc Connection_Manager.cc Message.cc Buffer.cc Bitset.cc logger.cc exception.cc myset.cc pTreeDB.cc RECON_DBManager.cc DB_info.h Utils.cc DBStruct.h)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
add_executable(recon_daemon ${SOURCE_FILES})

set(OpenPGP_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../OpenPGP)
set(NTL_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../lib/ntl)
set(GMP_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../lib/gmp)
set(CURLPP_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../curlpp-0.8.1)
set(DUMP_IMPORT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../dump_import)

target_link_libraries(recon_daemon mysqlcppconn)
target_link_libraries(recon_daemon gmp)
target_link_libraries(recon_daemon curl)
target_link_libraries(recon_daemon ${NTL_DIRECTORY}/lib/libntl.a)
target_link_libraries(recon_daemon ${GMP_DIRECTORY}/lib/libgmp.so)
target_link_libraries(recon_daemon ${CURLPP_DIRECTORY}/build/libcurlpp.a)
target_link_libraries(recon_daemon dump_import)

include_directories(${OpenPGP_DIRECTORY})
include_directories(${DUMP_IMPORT_DIRECTORY})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../boost_1_63_0)
include_directories(${GMP_DIRECTORY}/include)
include_directories(${NTL_DIRECTORY}/include)
include_directories(${CURLPP_DIRECTORY}/include)
