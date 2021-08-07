add_executable(peaks main.cpp peaks.cpp)

target_link_libraries(peaks recon_daemon)
target_link_libraries(peaks dump)
target_link_libraries(peaks common)
target_link_libraries(peaks import)
target_link_libraries(peaks unpacker)
target_link_libraries(peaks analyzer)
target_link_libraries(peaks ${libopenpgp})
target_link_libraries(peaks ${libntl})
target_link_libraries(peaks ${libgmp})
target_link_libraries(peaks mysqlcppconn)
target_link_libraries(peaks ${Boost_LIBRARIES})
target_link_libraries(peaks -Wl,--whole-archive pks -Wl,--no-whole-archive)
target_link_libraries(peaks -Wl,--whole-archive ${cppcms_lib} -Wl,--no-whole-archive)
target_link_libraries(peaks ${booster_lib})
link_directories(${CGI_HANDLER_DIR})
target_link_libraries(peaks curl)
target_link_libraries(peaks z)
target_link_libraries(peaks bz2)
target_link_libraries(peaks crypto)

if (${CMAKE_BUILD_TYPE} STREQUAL "Docker")
    target_link_libraries(peaks ${libmariadb})
    target_link_libraries(peaks ${libnghttp2})
    target_link_libraries(peaks ssl)
    target_link_libraries(peaks crypto)
    target_link_libraries(peaks pcre)
    target_link_libraries(peaks ssh2)
endif()

if (${CMAKE_BUILD_TYPE} STREQUAL "Docker")
add_custom_command(TARGET peaks POST_BUILD
    COMMAND strip peaks
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "Running strip on binary")
endif ()

if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
add_custom_command(TARGET peaks POST_BUILD
    COMMAND sha1sum peaks
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "Running checksum on binary")
endif ()

target_link_libraries(peaks dl)
target_link_libraries(peaks backtrace)
