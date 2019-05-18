cmake_minimum_required(VERSION 3.5.1)
project(analyzer)

add_definitions(-Dmpz_raw_64)

set(SOURCE_FILES DBManager.cc analyzer.cc DBStruct.h Math_Support.cc EC_point.cc ED_point.cc Elliptic_Curve.cc Edward_Curve.cc fastGCD.cc utils.cc Curve_point.h Curve.h)

add_library(analyzer ${SOURCE_FILES})
