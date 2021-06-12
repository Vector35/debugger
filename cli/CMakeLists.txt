cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(debugger-cli)

remove_definitions(-DUNICODE -D_UNICODE)

file(GLOB_RECURSE ADAPTER-SOURCES
        ${CMAKE_SOURCE_DIR}/src/adapters/*.cpp
        ${CMAKE_SOURCE_DIR}/src/adapters/*.h )

file(GLOB_RECURSE CLI-SOURCES
        ${CMAKE_SOURCE_DIR}/cli/src/*.cpp
        ${CMAKE_SOURCE_DIR}/cli/src/*.h )

remove_definitions(-DUNICODE)
add_executable(debugger-cli ${ADAPTER-SOURCES} ${CLI-SOURCES})

target_link_libraries(debugger-cli dbgeng.lib)

set_target_properties(debugger-cli PROPERTIES
        CXX_STANDARD 17
        CXX_VISIBILITY_PRESET hidden
        CXX_STANDARD_REQUIRED ON
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
        )
