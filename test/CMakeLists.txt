enable_testing()
add_test(NAME peaks-test
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/bin/peaks-test )

add_executable(peaks-test main.cc ../main/peaks.cc pTree.cc Utils.cc Bitset.cc)

target_link_libraries(peaks-test ${Boost_LIBRARIES})
target_link_libraries(peaks-test ${libntl})
target_link_libraries(peaks-test ${libgmp})
target_link_libraries(peaks-test recon_daemon)
target_link_libraries(peaks-test common)
if(${DBMANAGER} STREQUAL "MYSQL")
target_link_libraries(peaks-test mysqlcppconn)
endif()

if(${DBMANAGER} STREQUAL "MARIADB")
target_link_libraries(peaks-test mariadb)
endif()

if(${DBMANAGER} STREQUAL "MARIADBCPP")
    target_link_libraries(peaks-test ${mariadbpp})
    if(NOT ${CMAKE_BUILD_TYPE} STREQUAL "Docker")
        target_link_libraries(peaks-test mariadb)
    endif()
endif()

