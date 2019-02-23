cmake_minimum_required(VERSION 3.5.1)
project(peaks)
enable_testing()

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_CXX_FLAGS "-DGPG_COMPATIBLE -Wall -pthread -static-libgcc -lstdc++ -pipe")
add_definitions(-DGPG_COMPATIBLE)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -march=native -g3 -O0")
set(CMAKE_CXX_FLAGS_PROFILE "${CMAKE_CXX_FLAGS_DEBUG} -pg")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -march=native -Ofast")
set(CMAKE_CXX_FLAGS_DOCKER "${CMAKE_CXX_FLAGS} -march=x86-64 -mtune=generic -O3")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

set(OpenPGP_DIRECTORY ${CMAKE_SOURCE_DIR}/OpenPGP)
set(NTL_DIRECTORY ${CMAKE_SOURCE_DIR}/lib/ntl)
set(BOOST_ROOT ${CMAKE_SOURCE_DIR}/lib/boost)
set(DUMP_IMPORT_DIRECTORY ${CMAKE_SOURCE_DIR}/dump_import)
set(CGI_HANDLER_DIRECTORY ${CMAKE_SOURCE_DIR}/cgi_handler)
set(UNPACKER_DIRECTORY ${CMAKE_SOURCE_DIR}/unpacker)
set(CPPCMS_DIRECTORY ${CMAKE_SOURCE_DIR}/lib/cppcms)
set(GMP_DIRECTORY ${CMAKE_SOURCE_DIR}/lib/gmp)

include_directories(${OpenPGP_DIRECTORY})
include_directories(${DUMP_IMPORT_DIRECTORY})
include_directories(${CMAKE_SOURCE_DIR}/lib/boost/include)
include_directories(${GMP_DIRECTORY}/include)
include_directories(${NTL_DIRECTORY}/include)
include_directories(${CPPCMS_DIRECTORY}/include)
include_directories(${CGI_HANDLER_DIRECTORY})
include_directories(${UNPACKER_DIRECTORY})

add_subdirectory(cgi_handler)
add_subdirectory(dump_import)
add_subdirectory(recon_daemon)
add_subdirectory(unpacker)
add_subdirectory(analyzer)


find_package(Boost REQUIRED program_options)

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
target_link_libraries(peaks ${GMP_DIRECTORY}/lib/libgmp.so)
target_link_libraries(peaks dump_import)
target_link_libraries(peaks recon_daemon)
target_link_libraries(peaks unpacker)
target_link_libraries(peaks analyzer)
target_link_libraries(peaks -Wl,--whole-archive pks -Wl,--no-whole-archive)
