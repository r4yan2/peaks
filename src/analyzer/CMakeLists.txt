project(analyzer)

add_definitions(-Dmpz_raw_64)

set(SOURCE_FILES DBManager.cpp analyzer.cpp Math_Support.cpp EC_point.cpp ED_point.cpp Elliptic_Curve.cpp Edward_Curve.cpp fastGCD.cpp utils.cpp Curve_point.h Curve.h)

add_library(analyzer ${SOURCE_FILES})
