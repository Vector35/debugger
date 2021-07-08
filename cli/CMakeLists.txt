cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(debugger-cli)

add_definitions(-DFMT_HEADER_ONLY)
remove_definitions(-DUNICODE -D_UNICODE)

set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../src)
set(ADAPTER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../src/adapters)
set(ADAPTER_SOURCES ${SRC_DIR}/debugadapter.h ${ADAPTER_DIR}/gdbadapter.cpp ${ADAPTER_DIR}/gdbadapter.h ${ADAPTER_DIR}/rspconnector.cpp ${ADAPTER_DIR}/rspconnector.h ${ADAPTER_DIR}/socket.h)

if (WIN32)
    add_definitions(-DWIN32)
    set(ADAPTER_SOURCES ${ADAPTER_SOURCES} ${ADAPTER_DIR}/dbgengadapter.cpp ${ADAPTER_DIR}/dbgengadapter.h)
else()
endif()

file(GLOB_RECURSE CLI_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.h
        ${SRC_DIR}/vendor/*.cpp
        ${SRC_DIR}/vendor/*.h )

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
