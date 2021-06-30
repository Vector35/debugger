cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(debugger-cli)

remove_definitions(-DUNICODE -D_UNICODE)

set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(ADAPTER_DIR ${CMAKE_SOURCE_DIR}/src/adapters)
set(ADAPTER_SOURCES ${SRC_DIR}/debugadapter.h ${ADAPTER_DIR}/rspconnector.cpp ${ADAPTER_DIR}/rspconnector.h)

if (WIN32)
    add_definitions(-DWIN32)
    set(ADAPTER_SOURCES ${ADAPTER_SOURCES} ${ADAPTER_DIR}/dbgengadapter.cpp ${ADAPTER_DIR}/dbgengadapter.h)
else()
    set(ADAPTER_SOURCES ${ADAPTER_SOURCES}
            ${ADAPTER_DIR}/gdbadapter.cpp ${ADAPTER_DIR}/gdbadapter.h)
endif()

file(GLOB_RECURSE CLI_SOURCES
        ${CMAKE_SOURCE_DIR}/cli/src/*.cpp
        ${CMAKE_SOURCE_DIR}/cli/src/*.h
        ${CMAKE_SOURCE_DIR}/src/vendor/*.cpp
        ${CMAKE_SOURCE_DIR}/src/vendor/*.h )

add_executable(debugger-cli ${ADAPTER_SOURCES} ${CLI_SOURCES})

set(TARGET_LINK_LIBRARIES binaryninjaapi)
if (WIN32)
    set(TARGET_LINK_LIBRARIES ${TARGET_LINK_LIBRARIES} dbgeng.lib)
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
        )
