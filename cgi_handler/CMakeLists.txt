cmake_minimum_required(VERSION 3.8)
project(pks)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-march=native -DGPG_COMPATIBLE -static-libgcc -lstdc++ -pipe -Wall")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g3 -O0 -pg")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3")

set(SOURCE_FILES pks.cc db.cc utils.cc encoder/encoder.cc mitpgpskin.cc PacketReader.cc db_key.h content.h)

set(TEMPLATES_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/templates)
set(TEMPLATES ${TEMPLATES_FOLDER}/certificate.tmpl ${TEMPLATES_FOLDER}/index.tmpl ${TEMPLATES_FOLDER}/homepage.tmpl ${TEMPLATES_FOLDER}/vindex.tmpl)
add_custom_command(
        OUTPUT mitpgpskin.cc
        COMMAND cppcms_tmpl_cc ${TEMPLATES} -o mitpgpskin.cc
        DEPENDS ${TEMPLATES}
        )

add_library(pks ${SOURCE_FILES})

set(OpenPGP_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../OpenPGP)
include_directories(${OpenPGP_DIRECTORY})
link_directories(${OpenPGP_DIRECTORY})
set(Cppcms_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib/cppcms)

find_library(cppcms_lib
    NAMES libcppcms.so
    HINTS ${CMAKE_SOURCE_DIR}/lib/cppcms
    )
find_library(booster_lib
    NAMES libbooster.so
    HINTS ${CMAKE_SOURCE_DIR}/lib/cppcms/booster
    )

message("test: ${cppcms_lib} ${booster_lib}")

target_link_libraries(pks ${OpenPGP_DIRECTORY}/libOpenPGP.a)

find_package(Boost REQUIRED COMPONENTS system filesystem)

target_link_libraries(pks ${Boost_LIBRARIES})
target_link_libraries(pks mysqlcppconn)
target_link_libraries(pks gmp)
target_link_libraries(pks bz2)
target_link_libraries(pks z)
target_link_libraries(pks ${cppcms_lib})
target_link_libraries(pks ${booster_lib})
target_link_libraries(pks ${CMAKE_THREAD_LIBS_INIT})
