cmake_minimum_required(VERSION 2.8)
project(peaks)

set(CMAKE_CXX_STANDARD 14)
SET( CMAKE_EXPORT_COMPILE_COMMANDS ON )

add_definitions(-DGPG_COMPATIBLE)
add_definitions(-DBOOST_STACKTRACE_USE_BACKTRACE)

if (NOT DEFINED CMAKE_CXX_FLAGS OR "${CMAKE_CXX_FLAGS}" STREQUAL "")
    set(CMAKE_CXX_FLAGS "-Wall -pthread -lstdc++ -pipe")
endif ()

set (PROFILE OFF CACHE BOOL "Profiling")
if (PROFILE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg")
endif ()

set (BUILD_ANALYZER ON CACHE BOOL "Building with analyzer")
if (BUILD_ANALYZER)
    set(ANALYZER_DIR ${CMAKE_SOURCE_DIR}/src/analyzer)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DBUILD_ANALYZER")
endif()

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g3 -rdynamic -O0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3")
set(CMAKE_CXX_FLAGS_DOCKER "${CMAKE_CXX_FLAGS} -O2 -g -mtune=generic")
set(CMAKE_CXX_FLAGS_STATIC "${CMAKE_CXX_FLAGS_DOCKER}")

set(suffix "so")

if (${CMAKE_BUILD_TYPE} STREQUAL "Static")
    set(suffix "a")
    set(Boost_USE_STATIC_LIBS   ON)
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    SET(BUILD_SHARED_LIBS OFF)
    SET(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")
endif ()
message(STATUS "BUILD TYPE:     ${CMAKE_BUILD_TYPE}")

if (NOT DEFINED CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
endif ()

if (DEFINED CMAKE_LIB_PREFIX)
    set(LIB_DIR ${CMAKE_LIB_PREFIX})
else ()
    set(LIB_DIR ${CMAKE_SOURCE_DIR}/lib)
endif ()


set(LIBRARY_DIR ${LIB_DIR}/lib)
set(INCLUDE_DIR ${LIB_DIR}/include)
set(BIN_DIR ${LIB_DIR}/bin)
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(IMPORT_DIR ${CMAKE_SOURCE_DIR}/src/import)
set(DUMP_DIR ${CMAKE_SOURCE_DIR}/src/dump)
set(CGI_HANDLER_DIR ${CMAKE_SOURCE_DIR}/src/cgi_handler)
set(UNPACKER_DIR ${CMAKE_SOURCE_DIR}/src/unpacker)
set(COMMON_DIR ${CMAKE_SOURCE_DIR}/src/common)
set(RECON_DIR ${CMAKE_SOURCE_DIR}/src/recon_daemon)
set(MAIN_DIR ${CMAKE_SOURCE_DIR}/src/main)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)

find_package(Boost REQUIRED 
    unit_test_framework 
    program_options
    system
    filesystem
    )
find_library(cppcms_lib
    NAMES libcppcms.${suffix}
    HINTS ${LIBRARY_DIR}
    PATHS ${LIBRARY_DIR} NO_DEFAULT_PATH
    )
message(STATUS "CppCMS library:     ${cppcms_lib}")
find_library(booster_lib
    NAMES libbooster.${suffix}
    HINTS ${LIBRARY_DIR}
    PATHS ${LIBRARY_DIR} NO_DEFAULT_PATH
    )
message(STATUS "Booster library:     ${booster_lib}")

find_library(libopenpgp
    NAMES libOpenPGP.${suffix}
    HINTS ${LIBRARY_DIR}
    PATHS ${LIBRARY_DIR} NO_DEFAULT_PATH
    )
message(STATUS "PGP libraries:      ${libopenpgp}")

if (BUILD_ANALYZER)
find_library(libgmp
    NAMES libgmp.${suffix}
    HINTS ${LIBRARY_DIR}
    PATHS ${LIBRARY_DIR} NO_DEFAULT_PATH
    )
else ()
find_library(libgmp
    NAMES libgmp.${suffix}
    )
endif ()

message(STATUS "GMP libraries:      ${libgmp}")

find_library(libntl
    NAMES libntl.a
    HINTS ${LIBRARY_DIR}
    PATHS ${LIBRARY_DIR} NO_DEFAULT_PATH
    )
message(STATUS "NTL libraries:      ${libntl}")

include_directories(${INCLUDE_DIR})
include_directories(${SRC_DIR})
include_directories(${COMMON_DIR})
include_directories(${IMPORT_DIR})
include_directories(${CGI_HANDLER_DIR})
include_directories(${UNPACKER_DIR})
include_directories(${DUMP_DIR})
include_directories(${MAIN_DIR})
if (BUILD_ANALYZER)
    include_directories(${ANALYZER_DIR})
endif()
include_directories(${RECON_DIR})

add_subdirectory(${IMPORT_DIR})
add_subdirectory(${CGI_HANDLER_DIR})
add_subdirectory(${UNPACKER_DIR})
add_subdirectory(${DUMP_DIR})
add_subdirectory(${COMMON_DIR})
if (BUILD_ANALYZER)
add_subdirectory(${ANALYZER_DIR})
endif()
add_subdirectory(${RECON_DIR})
add_subdirectory(${MAIN_DIR})

add_subdirectory(test)
