cmake_minimum_required(VERSION 3.8)
project(pks)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS_DEBUG "-march=native -DGPG_COMPATIBLE -g3 -O0 -pthread -lbz2 -lgmp -lz -lcppcms -lmysqlcppconn -lbooster -static-libgcc -lstdc++ -pipe -Wall")
set(CMAKE_CXX_FLAGS_RELEASE "-march=native -DGPG_COMPATIBLE -O2 -pthread -lbz2 -lgmp -lz -lcppcms -lmysqlcppconn -lbooster -static-libgcc -pipe -Wall")

set(SOURCE_FILES pks.cc db.cc utils.cc encoder/encoder.cc mitpgpskin.cc PacketReader.cc db_key.h content.h DB_info.h)

set(TEMPLATES_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/templates)
set(TEMPLATES ${TEMPLATES_FOLDER}/certificate.tmpl ${TEMPLATES_FOLDER}/index.tmpl ${TEMPLATES_FOLDER}/homepage.tmpl ${TEMPLATES_FOLDER}/vindex.tmpl)
add_custom_command(
        OUTPUT mitpgpskin.cc
        COMMAND cppcms_tmpl_cc ${TEMPLATES} -o mitpgpskin.cc
        DEPENDS ${TEMPLATES}
        )

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
add_library(pks ${SOURCE_FILES})

set(OpenPGP_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../OpenPGP)
include_directories(${OpenPGP_DIRECTORY})
link_directories(${OpenPGP_DIRECTORY})

target_link_libraries(pks ${OpenPGP_DIRECTORY}/libOpenPGP.a)

find_package(Boost REQUIRED COMPONENTS system filesystem)

target_link_libraries(pks ${Boost_LIBRARIES})
target_link_libraries(pks mysqlcppconn)
target_link_libraries(pks gmp)
target_link_libraries(pks bz2)
target_link_libraries(pks z)
target_link_libraries(pks cppcms)
target_link_libraries(pks booster)
