cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(debugger-cli)

remove_definitions(-DUNICODE -D_UNICODE)

file(GLOB SOURCES *.cpp *.h)

add_executable(debugger-cli ${SOURCES})

if(UNIX AND NOT APPLE)
    target_link_libraries(debugger-cli debuggerapi pthread)
else()
    target_link_libraries(debugger-cli debuggerapi)
endif()

set_target_properties(debugger-cli PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin
        )
