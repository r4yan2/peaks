cmake_minimum_required(VERSION 3.9)
project(analyzer)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-march=native -Wall -static-libgcc -pthread -lstdc++ -pipe")

add_definitions(-DGPG_COMPATIBLE)
add_definitions(-Dmpz_raw_64)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g3 -O0")
set(CMAKE_CXX_FLAGS_PROFILE "${CMAKE_CXX_FLAGS_DEBUG} -pg")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -Ofast")

set(SOURCE_FILES DBManager.cc Thread_Pool.cc analyzer.cc DBStruct.h Math_Support.cc EC_point.cc ED_point.cc Elliptic_Curve.cc Edward_Curve.cc fastGCD.cc utils.cc Curve_point.h Curve.h)

add_library(analyzer ${SOURCE_FILES})

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


target_link_libraries(analyzer ${OpenPGP_DIRECTORY}/libOpenPGP.a)
target_link_libraries(analyzer ${NTL_DIR}/lib/libntl.a)
target_link_libraries(analyzer ${GMP_PARCHED_DIR}/lib/libgmp.so)
target_link_libraries(analyzer ${Boost_LIBRARIES}) 
target_link_libraries(analyzer mysqlcppconn) 
target_link_libraries(analyzer bz2)
target_link_libraries(analyzer z)
