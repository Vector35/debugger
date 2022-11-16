cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(debugger)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(DEMO)
    add_library(debugger STATIC debugger.cpp)
else()
    add_library(debugger SHARED debugger.cpp)
endif()

if(BN_INTERNAL_BUILD)
    set(LIBRARY_OUTPUT_DIRECTORY_PATH "${BN_CORE_PLUGIN_DIR}")
else()
    set(LIBRARY_OUTPUT_DIRECTORY_PATH "${CMAKE_BINARY_DIR}/out/plugins")
endif()

set_target_properties(debugger PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${LIBRARY_OUTPUT_DIRECTORY_PATH}
        RUNTIME_OUTPUT_DIRECTORY ${LIBRARY_OUTPUT_DIRECTORY_PATH}
        )

target_link_libraries(debugger debuggercore binaryninjaapi)
target_include_directories(debugger PRIVATE ${PROJECT_SOURCE_DIR}/../core)
