cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(debuggerapi)

file(GLOB BN_DEBUGGER_API_SOURCES *.cpp *.h)
add_library(debuggerapi STATIC ${BN_DEBUGGER_API_SOURCES})

target_include_directories(debuggerapi
        PUBLIC ${PROJECT_SOURCE_DIR})

target_link_libraries(debuggerapi PUBLIC debuggercore)

set_target_properties(debuggerapi PROPERTIES
        CXX_STANDARD 17
        CXX_VISIBILITY_PRESET hidden
        CXX_STANDARD_REQUIRED ON
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/out)

if (NOT DEMO)
    add_subdirectory(python)
endif()