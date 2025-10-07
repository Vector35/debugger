cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

# Core unit tests
project(core-tests)

include(FetchContent)

FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_MakeAvailable(googletest)
# Find required packages
#find_package(GTest REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
)

enable_testing()

# Create test executable
add_executable(miparser_test miparser_test.cpp)
target_compile_features(miparser_test PRIVATE cxx_std_20)
set_target_properties(miparser_test PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
)

# Link dependencies
target_link_libraries(miparser_test
    GTest::gtest
    debuggercore  # Link against the core library
)

target_sources(miparser_test PRIVATE ../adapters/gdbmiconnector.cpp)

# Add test to CTest
include(GoogleTest)
gtest_discover_tests(miparser_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
