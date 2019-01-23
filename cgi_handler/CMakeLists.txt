cmake_minimum_required(VERSION 3.8)
project(pks)

set(SOURCE_FILES pks.cc db.cc utils.cc encoder/encoder.cc mitpgpskin.cc PacketReader.cc db_key.h content.h)

set(TEMPLATES_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/templates)
set(TEMPLATES ${TEMPLATES_FOLDER}/certificate.tmpl ${TEMPLATES_FOLDER}/index.tmpl ${TEMPLATES_FOLDER}/homepage.tmpl ${TEMPLATES_FOLDER}/vindex.tmpl)
set(OpenPGP_DIRECTORY ${CMAKE_SOURCE_DIR}/OpenPGP)
set(CPPCMS_DIRECTORY ${CMAKE_SOURCE_DIR}/lib/cppcms)

set(CPPCMS_TMPL_CC ${CPPCMS_DIRECTORY}/bin/cppcms_tmpl_cc)

add_custom_command(
        OUTPUT mitpgpskin.cc
        COMMAND ${CPPCMS_TMPL_CC} ${TEMPLATES} -o mitpgpskin.cc
        DEPENDS ${TEMPLATES}
        )

add_library(pks ${SOURCE_FILES})

find_library(cppcms_lib
    NAMES libcppcms.so
    HINTS ${CPPCMS_DIRECTORY}/lib/
    )
find_library(booster_lib
    NAMES libbooster.so
    HINTS ${CPPCMS_DIRECTORY}/lib/
    )

link_directories(${OpenPGP_DIRECTORY})
target_link_libraries(pks ${OpenPGP_DIRECTORY}/libOpenPGP.a)
target_link_libraries(pks ${Boost_LIBRARIES})
target_link_libraries(pks mysqlcppconn)
target_link_libraries(pks gmp)
target_link_libraries(pks bz2)
target_link_libraries(pks z)
target_link_libraries(pks ${cppcms_lib})
target_link_libraries(pks ${booster_lib})
target_link_libraries(pks ${CMAKE_THREAD_LIBS_INIT})
