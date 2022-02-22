cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(debuggerui)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

file(GLOB SOURCES *.cpp *.h)
list(FILTER SOURCES EXCLUDE REGEX moc_.*)
list(FILTER SOURCES EXCLUDE REGEX qrc_.*)

if(DEMO)
    add_library(debuggerui STATIC ${SOURCES})
else()
    add_library(debuggerui SHARED ${SOURCES})
endif()

set_target_properties(debuggerui PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
        LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
        RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
        )

target_link_libraries(debuggerui debuggerapi binaryninjaui binaryninjaapi Qt6::Core Qt6::Gui Qt6::Widgets)

include_directories(../vendor)
