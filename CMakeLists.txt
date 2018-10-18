cmake_minimum_required(VERSION 3.5.1)
project(peaks)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-march=native -DGPG_COMPATIBLE -Wall -pthread -static-libgcc -lstdc++ -pipe")
add_definitions(-DGPG_COMPATIBLE)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g3 -pg")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3 -Werror")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

add_definitions(-DTMP_FOLDER_CSV="/tmp/dump_import/")
add_definitions(-DERROR_FOLDER="/tmp/gpg_keyserver_ERRORS/dump_import_errors/")
add_definitions(-DDEFAULT_DUMP_PATH="/tmp/pgp_dump/")

set(OpenPGP_DIRECTORY ${CMAKE_SOURCE_DIR}/OpenPGP)
include_directories(${OpenPGP_DIRECTORY})
set(NTL_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib/ntl)
set(DUMP_IMPORT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/dump_import)
set(CGI_HANDLER_DIRECTORY ${CMAKE_SOURCE_DIR}/cgi_handler)
include_directories(${DUMP_IMPORT_DIRECTORY})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/boost_1_63_0)
include_directories(${GMP_DIRECTORY}/include)
include_directories(${NTL_DIRECTORY}/include)
include_directories(${CURLPP_DIRECTORY}/include)
include_directories(${CGI_HANDLER_DIRECTORY})


add_subdirectory(cgi_handler)
add_subdirectory(dump_import)
add_subdirectory(recon_daemon)

find_package(Boost REQUIRED COMPONENTS program_options)

add_executable(peaks peaks.cc)

if (${CMAKE_BUILD_TYPE} STREQUAL "Release")
set(STRIP "peaks_stripped")
add_custom_command(TARGET peaks POST_BUILD
    COMMAND strip -o peaks_stripped peaks
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
    COMMENT "Running strip on binary")
endif ()

add_custom_command(TARGET peaks POST_BUILD
    COMMAND sha1sum peaks
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
    COMMENT "Running checksum on binary")

link_directories(${CGI_HANDLER_DIRECTORY})
target_link_libraries(peaks ${Boost_LIBRARIES})
target_link_libraries(peaks ${NTL_DIRECTORY}/lib/libntl.a)
target_link_libraries(peaks dump_import)
target_link_libraries(peaks recon_daemon)
target_link_libraries(peaks -Wl,--whole-archive pks -Wl,--no-whole-archive)
