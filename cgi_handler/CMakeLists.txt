cmake_minimum_required(VERSION 3.8)
project(pks)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS_DEBUG "-march=native -DGPG_COMPATIBLE -g -O0 -pthread -lbz2 -lgmp -lz -lcppcms -lmysqlcppconn -lbooster -static-libgcc -lstdc++ -pipe -Wall")
set(CMAKE_CXX_FLAGS_RELEASE "-march=native -DGPG_COMPATIBLE -O2 -g3 -pthread -lbz2 -lgmp -lz -lcppcms -lmysqlcppconn -lbooster -static-libgcc -pipe 
-Werror -Wall")
set(SOURCE_FILES pks.cc db.cc utils.cc encoder/encoder.cc mitpgpskin.cc PacketReader.cc db_key.h content.h DB_info.h)

set(TEMPLATES_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/templates)
set(TEMPLATES ${TEMPLATES_FOLDER}/certificate.tmpl ${TEMPLATES_FOLDER}/index.tmpl
        ${TEMPLATES_FOLDER}/homepage.tmpl ${TEMPLATES_FOLDER}/vindex.tmpl)
add_custom_command(
        OUTPUT mitpgpskin.cc
        COMMAND cppcms_tmpl_cc ${TEMPLATES} -o mitpgpskin.cc
        DEPENDS ${TEMPLATES}
        )

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
add_executable(pks ${SOURCE_FILES})

set(OpenPGP_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../OpenPGP)
include_directories(${OpenPGP_DIRECTORY})
link_directories(${OpenPGP_DIRECTORY})

target_link_libraries(pks ${OpenPGP_DIRECTORY}/libOpenPGP.a)

