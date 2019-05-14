cmake_minimum_required(VERSION 2.8)
project(peaks)
enable_testing()

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_CXX_FLAGS "-DGPG_COMPATIBLE -Wall -pthread -lstdc++ -pipe")

if(NOT DEFINED DBMANAGER)
    set(DBMANAGER "MARIADBCPP")
endif()

add_definitions(-DGPG_COMPATIBLE)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -march=native -g3 -O0")
set(CMAKE_CXX_FLAGS_PROFILE "${CMAKE_CXX_FLAGS_DEBUG} -pg")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -march=native -Ofast")
set(CMAKE_CXX_FLAGS_DOCKER "${CMAKE_CXX_FLAGS} -march=x86-64 -mtune=generic -Os")

#TODO add proper static build support
#if (${CMAKE_BUILD_TYPE} STREQUAL "Docker")
#    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
#    SET(BUILD_SHARED_LIBS OFF)
#    SET(CMAKE_EXE_LINKER_FLAGS "-static")
#endif ()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

set(OpenPGP_DIRECTORY ${CMAKE_SOURCE_DIR}/OpenPGP)
set(LIB_DIR ${CMAKE_SOURCE_DIR}/lib)
set(NTL_DIRECTORY ${LIB_DIR}/ntl)
set(BOOST_ROOT ${LIB_DIR}/boost)
set(CPPCMS_DIRECTORY ${LIB_DIR}/cppcms)
set(GMP_DIRECTORY ${LIB_DIR}/gmp)
set(IMPORT_DIRECTORY ${CMAKE_SOURCE_DIR}/import)
set(DUMP_DIRECTORY ${CMAKE_SOURCE_DIR}/dump)
set(CGI_HANDLER_DIRECTORY ${CMAKE_SOURCE_DIR}/cgi_handler)
set(UNPACKER_DIRECTORY ${CMAKE_SOURCE_DIR}/unpacker)
set(COMMON_DIRECTORY ${CMAKE_SOURCE_DIR}/common)

if(${DBMANAGER} STREQUAL "MYSQL")
    set(SOURCE_DB Mysql_DBManager.cc)
    add_compile_definitions(USE_MYSQL)
endif()

if(${DBMANAGER} STREQUAL "MARIADBC")
    set(SOURCE_DB MariadbC_DBManager.cc)
    add_compile_definitions(USE_MARIADB_C)
endif()


if(${DBMANAGER} STREQUAL "MARIADBCPP")
    set(SOURCE_DB MariadbCpp_DBManager.cc)
    add_compile_definitions(USE_MARIADB_CPP)
    set(MARIADBCPP_DIRECTORY ${LIB_DIR}/mariadbpp)
    include_directories(${MARIADBCPP_DIRECTORY}/include)
    include_directories(/usr/include/mariadb)
endif()

find_package(Boost REQUIRED 
    program_options
    system
    filesystem
    )
find_library(cppcms_lib
    NAMES libcppcms.so libcppcms.a
    HINTS ${CPPCMS_DIRECTORY}/lib/
    )
find_library(booster_lib
    NAMES libbooster.so libbooster.a
    HINTS ${CPPCMS_DIRECTORY}/lib/
    )

include_directories(${OpenPGP_DIRECTORY})
include_directories(${CPPCMS_DIRECTORY}/include)
include_directories(${IMPORT_DIRECTORY})
include_directories(${BOOST_ROOT}/include)
include_directories(${GMP_DIRECTORY}/include)
include_directories(${NTL_DIRECTORY}/include)
include_directories(${CGI_HANDLER_DIRECTORY})
include_directories(${UNPACKER_DIRECTORY})
include_directories(${DUMP_DIRECTORY})
include_directories(${COMMON_DIRECTORY})

add_subdirectory(common)
add_subdirectory(main)
add_subdirectory(cgi_handler)
add_subdirectory(import)
add_subdirectory(recon_daemon)
add_subdirectory(unpacker)
add_subdirectory(analyzer)
add_subdirectory(dump)
