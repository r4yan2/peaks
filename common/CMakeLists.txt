cmake_minimum_required(VERSION 3.5.1)
project(common)

set(SOURCE_FILES utils.cc Thread_Pool.cc)
add_library(common ${SOURCE_FILES})
