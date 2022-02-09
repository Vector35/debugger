cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(debugger-cli)

remove_definitions(-DUNICODE -D_UNICODE)

set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../core)
set(ADAPTER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../core/adapters)
set(ADAPTER_SOURCES
        ${SRC_DIR}/debugadapter.h ${SRC_DIR}/debugadapter.cpp
        ${ADAPTER_DIR}/gdbadapter.cpp ${ADAPTER_DIR}/gdbadapter.h
        ${ADAPTER_DIR}/lldbadapter.cpp ${ADAPTER_DIR}/lldbadapter.h
        ${ADAPTER_DIR}/rspconnector.cpp ${ADAPTER_DIR}/rspconnector.h
        ${ADAPTER_DIR}/socket.h)

if (WIN32)
    add_definitions(-DWIN32)
    set(ADAPTER_SOURCES ${ADAPTER_SOURCES} ${ADAPTER_DIR}/dbgengadapter.cpp ${ADAPTER_DIR}/dbgengadapter.h)
endif()

file(GLOB_RECURSE CLI_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.h
        ${SRC_DIR}/vendor/*.cpp
        ${SRC_DIR}/vendor/*.h )

if (WIN32)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
endif()

# include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../test/googletest)
# add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../test/googletest ${CMAKE_CURRENT_SOURCE_DIR}/../test/testbins)

add_executable(debugger-cli ${ADAPTER_SOURCES} ${CLI_SOURCES})

set(TARGET_LINK_LIBRARIES binaryninjaapi)
if (WIN32)
    set(TARGET_LINK_LIBRARIES ${TARGET_LINK_LIBRARIES} dbgeng.lib wsock32 ws2_32)
else()
    set(TARGET_LINK_LIBRARIES ${TARGET_LINK_LIBRARIES} libpthread.so.0)
endif()

target_link_libraries(debugger-cli ${TARGET_LINK_LIBRARIES})

set_target_properties(debugger-cli PROPERTIES
        CXX_STANDARD 17
        CXX_VISIBILITY_PRESET hidden
        CXX_STANDARD_REQUIRED ON
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin
        )

enable_testing()
include_directories(${ADAPTER_DIR})

# file(GLOB_RECURSE TEST_SOURCES
#         ${CMAKE_CURRENT_SOURCE_DIR}/../src/vendor/*.cpp
#         ${CMAKE_CURRENT_SOURCE_DIR}/../src/vendor/*.h)

# add_executable(execute_test
#         ${ADAPTER_SOURCES}
#         ${TEST_SOURCES}
#         ${CMAKE_CURRENT_SOURCE_DIR}/../test/execute_test.cpp)

# target_link_libraries(execute_test ${TARGET_LINK_LIBRARIES} gtest_main)

# set_target_properties(execute_test PROPERTIES
#         CXX_STANDARD 17
#         CXX_VISIBILITY_PRESET hidden
#         CXX_STANDARD_REQUIRED ON
#         VISIBILITY_INLINES_HIDDEN ON
#         POSITION_INDEPENDENT_CODE ON
        # ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../test/testbins/lib"
        # LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../test/testbins/lib"
        # RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../test/testbins"
        # )

# include(GoogleTest)
# gtest_discover_tests(execute_test)