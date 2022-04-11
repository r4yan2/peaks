if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    enable_testing()
    add_test(NAME peaks-test
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
            COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/bin/peaks-test )
    
    add_executable(peaks-test main.cpp config.cpp ./recon/pTree.cpp Utils.cpp ./recon/Bitset.cpp)
    
    target_link_libraries(peaks-test recon_daemon)
    target_link_libraries(peaks-test common)
    target_link_libraries(peaks-test ${libopenpgp})
    target_link_libraries(peaks-test ${Boost_LIBRARIES})
    target_link_libraries(peaks-test ${libntl})
    target_link_libraries(peaks-test ${libgmp})
    target_link_libraries(peaks-test mysqlcppconn)
    target_link_libraries(peaks-test z)
    target_link_libraries(peaks-test bz2)
endif ()
