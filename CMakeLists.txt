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
set(CMAKE_CXX_FLAGS_DOCKER "${CMAKE_CXX_FLAGS} -march=x86-64 -mtune=generic -Os -no-pie")

if (${CMAKE_BUILD_TYPE} STREQUAL "Docker")
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    SET(BUILD_SHARED_LIBS OFF)
    SET(CMAKE_EXE_LINKER_FLAGS "-static")
endif ()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

set(OPENPGP_DIR ${CMAKE_SOURCE_DIR}/OpenPGP)
set(LIB_DIR ${CMAKE_SOURCE_DIR}/lib)
set(NTL_DIR ${LIB_DIR}/ntl)
set(BOOST_ROOT ${LIB_DIR}/boost)
set(CPPCMS_DIR ${LIB_DIR}/cppcms)
set(GMP_DIR ${LIB_DIR}/gmp)
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
    set(MARIADBCPP_DIR ${LIB_DIR}/mariadbpp)
    include_directories(${MARIADBCPP_DIR}/include)
    include_directories(/usr/include/mysql)
    find_library(mariadbpp
        NAMES libmariadbclientpp.a
        HINTS ${MARIADBCPP_DIR}/lib/
        )
endif()

find_package(Boost REQUIRED 
    program_options
    system
    filesystem
    )
find_library(cppcms_lib
    NAMES libcppcms.so libcppcms.a
    HINTS ${CPPCMS_DIR}/lib/
    )
find_library(booster_lib
    NAMES libbooster.so libbooster.a
    HINTS ${CPPCMS_DIR}/lib/
    )

find_library(libopenpgp
    NAMES libOpenPGP.a
    HINTS ${OPENPGP_DIR}/
    )

find_library(libgmp
    NAMES libgmp.so libgmp.a
    HINTS ${GMP_DIR}/lib/
    )

find_library(libntl
    NAMES libntl.a
    HINTS ${NTL_DIR}/lib
    )
if(${CMAKE_BUILD_TYPE} STREQUAL "Docker")
find_library(libnghttp2
    NAMES libnghttp2.a
    HINTS ${LIB_DIR}/nghttp2/lib/
    )
find_library(libmariadb
    NAMES libmariadbclient.a
    HINTS ${LIB_DIR}/mariadb/lib/mariadb/
    )
endif()
include_directories(${OPENPGP_DIR})
include_directories(${CPPCMS_DIR}/include)
include_directories(${IMPORT_DIRECTORY})
include_directories(${BOOST_ROOT}/include)
include_directories(${GMP_DIR}/include)
include_directories(${NTL_DIR}/include)
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
