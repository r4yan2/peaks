cmake_minimum_required(VERSION 3.9)
project(analyzer)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-march=native -Wall -lbz2 -lz \
            -lmysqlcppconn -static-libgcc -pthread -lstdc++ -pipe -lboost_system -lboost_filesystem")

add_definitions(-DGPG_COMPATIBLE)
add_definitions(-Dmpz_raw_64)
add_definitions(-DTMP_FOLDER_CSV="/var/lib/mysql-files/gpg_keyserver/analyzer/")
add_definitions(-DERROR_FOLDER="/tmp/gpg_keyserver_ERRORS/analyzer_errors/")
add_definitions(-DTMP_FOLDER_GCD="/tmp/fastGCD/")

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -Ofast -Werror")

set(SOURCE_FILES main.cc DBManager.cc Thread_Pool.cc analyzer.cc DBStruct.h Math_Support.cc EC_point.cc
        ED_point.cc Elliptic_Curve.cc Edward_Curve.cc fastGCD.cc utils.cc Curve_point.h Curve.h DB_info.h)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
add_executable(analyzer ${SOURCE_FILES})

set(OpenPGP_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../OpenPGP)
include_directories(${OpenPGP_DIRECTORY})
link_directories(${OpenPGP_DIRECTORY})

set(LIB_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../lib)

set(NTL_DIR ${LIB_DIRECTORY}/ntl)
include_directories(${NTL_DIR}/include)
link_directories(${NTL_DIR}/lib)

set(GMP_PARCHED_DIR ${LIB_DIRECTORY}/gmp)
include_directories(${GMP_PARCHED_DIR}/include)
link_directories(${GMP_PARCHED_DIR}/lib)

find_package(Boost REQUIRED COMPONENTS system filesystem)

target_link_libraries(analyzer ${OpenPGP_DIRECTORY}/libOpenPGP.a)
target_link_libraries(analyzer ${NTL_DIR}/lib/libntl.a)
target_link_libraries(analyzer ${GMP_PARCHED_DIR}/lib/libgmp.so)
target_link_libraries(analyzer ${Boost_LIBRARIES}) 
target_link_libraries(analyzer mysqlcppconn) 
