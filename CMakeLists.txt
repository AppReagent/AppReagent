cmake_minimum_required(VERSION 3.28)
project(area)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

include(FetchContent)

FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)

FetchContent_Declare(
    yoga
    URL https://github.com/facebook/yoga/archive/refs/tags/v3.2.1.tar.gz
    SOURCE_SUBDIR yoga
)

FetchContent_Declare(
    capstone
    URL https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.1.tar.gz
)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(json yoga capstone)

find_package(PostgreSQL REQUIRED)
find_package(CURL REQUIRED)

include_directories(include)

file(GLOB_RECURSE SOURCES src/*.cpp)
add_executable(area ${SOURCES})
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

target_link_libraries(area PRIVATE
    nlohmann_json::nlohmann_json
    yogacore
    PostgreSQL::PostgreSQL
    CURL::libcurl
    Threads::Threads
    OpenSSL::Crypto
    capstone
)

# --- Tests ---

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

# Library target for test linking (everything except main.cpp)
file(GLOB_RECURSE LIB_SOURCES src/*.cpp)
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/main\\.cpp$")
add_library(area_lib STATIC ${LIB_SOURCES})
target_link_libraries(area_lib PUBLIC
    nlohmann_json::nlohmann_json
    yogacore
    PostgreSQL::PostgreSQL
    CURL::libcurl
    Threads::Threads
    OpenSSL::Crypto
    capstone
)
target_include_directories(area_lib PUBLIC include)

file(GLOB TEST_SOURCES tests/*.cpp)
add_executable(area_tests ${TEST_SOURCES})
target_link_libraries(area_tests PRIVATE
    area_lib
    GTest::gtest_main
)
target_compile_definitions(area_tests PRIVATE
    PROMPTS_DIR="${CMAKE_SOURCE_DIR}/prompts"
)

include(GoogleTest)
gtest_discover_tests(area_tests)
