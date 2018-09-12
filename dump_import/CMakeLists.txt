cmake_minimum_required(VERSION 3.9)
project(dump_import)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-march=native -Wall -lbz2 -lz \
            -lmysqlcppconn -static-libgcc -pthread -lstdc++ -pipe -lgmp -lboost_system -lboost_filesystem")

add_definitions(-DGPG_COMPATIBLE)
add_definitions(-DTMP_FOLDER_CSV="/tmp/dump_import/")
add_definitions(-DERROR_FOLDER="/tmp/gpg_keyserver_ERRORS/dump_import_errors/")
add_definitions(-DDEFAULT_DUMP_PATH="/tmp/pgp_dump/")

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3 -Werror")
set(BOOST_LIBRARYDIR "/usr/local/include/boost")
set(BOOST_ROOT "/usr/local/include")


#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

#set(OpenPGP_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../OpenPGP)
set(SOURCE_FILES dump_import.cc DBManager.cc Thread_Pool.cc unpacker.cc DBStruct.h utils.cc Key_Tools.cc DB_info.h)
add_library(dump_import ${SOURCE_FILES})
include_directories(${OpenPGP_DIRECTORY})

find_package(Boost REQUIRED COMPONENTS system filesystem)

target_link_libraries(dump_import ${OpenPGP_DIRECTORY}/libOpenPGP.a gmp bz2 mysqlcppconn z ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
