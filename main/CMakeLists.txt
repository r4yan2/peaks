add_executable(peaks peaks.cc)

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

target_link_libraries(peaks import)
target_link_libraries(peaks recon_daemon)
target_link_libraries(peaks unpacker)
target_link_libraries(peaks analyzer)
target_link_libraries(peaks dump)
target_link_libraries(peaks common)
target_link_libraries(peaks pks)
link_directories(${CGI_HANDLER_DIRECTORY})
target_link_libraries(peaks ${Boost_LIBRARIES})
target_link_libraries(peaks ${OpenPGP_DIRECTORY}/libOpenPGP.a)

if(${DBMANAGER} STREQUAL "MYSQL")
target_link_libraries(peaks mysqlcppconn)
endif()

if(${DBMANAGER} STREQUAL "MARIADB")
target_link_libraries(peaks mariadb)
endif()

if(${DBMANAGER} STREQUAL "MARIADBCPP")
    target_link_libraries(peaks ${MARIADBCPP_DIRECTORY}/lib/libmariadbclientpp.a)
    target_link_libraries(peaks mariadb)
endif()

target_link_libraries(peaks z)
target_link_libraries(peaks curl)
target_link_libraries(peaks bz2)
target_link_libraries(peaks ${GMP_DIRECTORY}/lib/libgmp.so)
target_link_libraries(peaks ${NTL_DIRECTORY}/lib/libntl.a)
target_link_libraries(peaks ${booster_lib})
target_link_libraries(peaks -Wl,--whole-archive ${cppcms_lib} -Wl,--no-whole-archive)
