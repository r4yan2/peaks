cmake_minimum_required(VERSION 2.8)
project(peaks)

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_CXX_FLAGS "-DGPG_COMPATIBLE -Wall -pthread -lstdc++ -pipe")

add_definitions(-DGPG_COMPATIBLE)
add_definitions(-DBOOST_STACKTRACE_USE_BACKTRACE)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -march=native -g3 -rdynamic -O0")
set(CMAKE_CXX_FLAGS_PROFILE "${CMAKE_CXX_FLAGS_DEBUG} -pg")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -march=native -Ofast")
set(CMAKE_CXX_FLAGS_DOCKER "${CMAKE_CXX_FLAGS} -march=x86-64 -mtune=generic -Os")

if (${CMAKE_BUILD_TYPE} STREQUAL "Docker")
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    SET(BUILD_SHARED_LIBS OFF)
    SET(CMAKE_EXE_LINKER_FLAGS "-static")
endif ()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

set(OPENPGP_DIR ${CMAKE_SOURCE_DIR}/OpenPGP)
set(LIB_DIR ${CMAKE_SOURCE_DIR}/lib)
set(BIN_DIR ${CMAKE_SOURCE_DIR}/lib/bin)
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(LIBRARY_DIR ${CMAKE_SOURCE_DIR}/lib/lib)
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/lib/include)

set(IMPORT_DIR ${CMAKE_SOURCE_DIR}/src/import)
set(DUMP_DIR ${CMAKE_SOURCE_DIR}/src/dump)
set(CGI_HANDLER_DIR ${CMAKE_SOURCE_DIR}/src/cgi_handler)
set(UNPACKER_DIR ${CMAKE_SOURCE_DIR}/src/unpacker)
set(COMMON_DIR ${CMAKE_SOURCE_DIR}/src/common)
set(RECON_DIR ${CMAKE_SOURCE_DIR}/src/recon_daemon)
set(MAIN_DIR ${CMAKE_SOURCE_DIR}/src/main)
set(ANALYZER_DIR ${CMAKE_SOURCE_DIR}/src/analyzer)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)

find_package(Boost REQUIRED 
    unit_test_framework 
    program_options
    system
    filesystem
    )
find_library(cppcms_lib
    NAMES libcppcms.so libcppcms.a
    HINTS ${LIBRARY_DIR}
    )
find_library(booster_lib
    NAMES libbooster.so libbooster.a
    HINTS ${LIBRARY_DIR}
    )

find_library(libopenpgp
    NAMES libOpenPGP.a
    HINTS ${LIBRARY_DIR}
    )
message(STATUS "PGP libraries:      ${libopenpgp}")

find_library(libgmp
    NAMES libgmp.a
    PATHS ${LIBRARY_DIR} NO_DEFAULT_PATH
    )
message(STATUS "GMP libraries:      ${libgmp}")

find_library(libntl
    NAMES libntl.a
    HINTS ${LIBRARY_DIR}
    )
message(STATUS "NTL libraries:      ${libntl}")

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

include_directories(${INCLUDE_DIR})
include_directories(${SRC_DIR})
include_directories(${OPENPGP_DIR})
include_directories(${COMMON_DIR})
include_directories(${IMPORT_DIR})
include_directories(${CGI_HANDLER_DIR})
include_directories(${UNPACKER_DIR})
include_directories(${DUMP_DIR})
include_directories(${MAIN_DIR})
include_directories(${ANALYZER_DIR})
include_directories(${RECON_DIR})

add_subdirectory(${IMPORT_DIR})
add_subdirectory(${CGI_HANDLER_DIR})
add_subdirectory(${UNPACKER_DIR})
add_subdirectory(${DUMP_DIR})
add_subdirectory(${COMMON_DIR})
add_subdirectory(${ANALYZER_DIR})
add_subdirectory(${RECON_DIR})
add_subdirectory(${MAIN_DIR})

add_subdirectory(test)
