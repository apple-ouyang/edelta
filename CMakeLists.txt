cmake_minimum_required(VERSION 3.10.0)
project(edelta VERSION 0.1.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 11)

aux_source_directory(src/ SRC)
aux_source_directory(util/ UTIL)

include_directories(.)

add_library(edelta ${SRC} ${UTIL})

option(ENABLE_TEST OFF)
if(ENABLE_TEST)
  add_subdirectory(tests)
endif()