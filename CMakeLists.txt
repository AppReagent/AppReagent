cmake_minimum_required(VERSION 3.28)
project(area)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

include_directories(include)

file(GLOB SOURCES src/*.cpp)
add_executable(area ${SOURCES})
