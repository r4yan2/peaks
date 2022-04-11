add_executable(peaks main.cpp)

if (DEFINED CMAKE_INSTALL_PREFIX)
    install(TARGETS peaks DESTINATION ${CMAKE_INSTALL_PREFIX})
endif ()

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

if (${CMAKE_BUILD_TYPE} STREQUAL "Static")
    target_link_libraries(peaks icuio)
    target_link_libraries(peaks icui18n)
    target_link_libraries(peaks icuuc)
    target_link_libraries(peaks icudata)
    target_link_libraries(peaks pcre)
    target_link_libraries(peaks crypto)
endif()

#if (${CMAKE_BUILD_TYPE} STREQUAL "Docker")
#add_custom_command(TARGET peaks POST_BUILD
#    COMMAND strip peaks
#    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
#    COMMENT "Running strip on binary")
#endif ()

if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
add_custom_command(TARGET peaks POST_BUILD
    COMMAND sha1sum peaks
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "Running checksum on binary")
endif ()

target_link_libraries(peaks dl)
