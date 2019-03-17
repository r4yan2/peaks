add_executable(peaks peaks.cc)
add_executable(peaks-test test/pTree.cc)

if (${CMAKE_BUILD_TYPE} STREQUAL "Release")
set(STRIP "peaks_stripped")
add_custom_command(TARGET peaks POST_BUILD
    COMMAND strip -o peaks_stripped peaks
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "Running strip on binary")
endif ()

add_custom_command(TARGET peaks POST_BUILD
    COMMAND sha1sum peaks
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "Running checksum on binary")

add_test(NAME peaks-test
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/bin/peaks-test )

target_link_libraries(peaks import)
target_link_libraries(peaks recon_daemon)
target_link_libraries(peaks unpacker)
target_link_libraries(peaks analyzer)
target_link_libraries(peaks dump)
target_link_libraries(peaks common)
target_link_libraries(peaks -Wl,--whole-archive pks -Wl,--no-whole-archive)
link_directories(${CGI_HANDLER_DIRECTORY})
target_link_libraries(peaks ${Boost_LIBRARIES})
target_link_libraries(peaks ${libopenpgp})

if(${DBMANAGER} STREQUAL "MYSQL")
target_link_libraries(peaks mysqlcppconn)
endif()

if(${DBMANAGER} STREQUAL "MARIADB")
target_link_libraries(peaks mariadb)
endif()

if(${DBMANAGER} STREQUAL "MARIADBCPP")
    target_link_libraries(peaks ${mariadbpp})
    if(NOT ${CMAKE_BUILD_TYPE} STREQUAL "Docker")
        target_link_libraries(peaks mariadb)
    endif()
endif()

target_link_libraries(peaks z)
target_link_libraries(peaks curl)
target_link_libraries(peaks bz2)
target_link_libraries(peaks ${libgmp})
target_link_libraries(peaks ${libntl})
target_link_libraries(peaks ${booster_lib})
target_link_libraries(peaks -Wl,--whole-archive ${cppcms_lib} -Wl,--no-whole-archive)

if (${CMAKE_BUILD_TYPE} STREQUAL "Docker")
    target_link_libraries(peaks ${libmariadb})
    target_link_libraries(peaks ${libnghttp2})
    target_link_libraries(peaks ssl)
    target_link_libraries(peaks crypto)
    target_link_libraries(peaks pcre)
    target_link_libraries(peaks ssh2)
endif()

target_link_libraries(peaks ${booster_lib})
target_link_libraries(peaks ${libgmp})

target_link_libraries(peaks-test ${Boost_LIBRARIES})
target_link_libraries(peaks-test ${NTL_DIRECTORY}/lib/libntl.a)
target_link_libraries(peaks-test ${GMP_DIRECTORY}/lib/libgmp.so)
target_link_libraries(peaks-test recon_daemon)
