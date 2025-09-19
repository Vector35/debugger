cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(debuggerui)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

file(GLOB SOURCES CONFIGURE_DEPENDS *.cpp *.h ../debuggerui.qrc)
list(FILTER SOURCES EXCLUDE REGEX moc_.*)
list(FILTER SOURCES EXCLUDE REGEX qrc_.*)
if (NOT WIN32)
    list(REMOVE_ITEM SOURCES ${PROJECT_SOURCE_DIR}/ttdrecord.h)
    list(REMOVE_ITEM SOURCES ${PROJECT_SOURCE_DIR}/ttdrecord.cpp)
else()
    list(APPEND SOURCES ${PROJECT_SOURCE_DIR}/../vendor/pugixml/pugixml.cpp)
    list(APPEND SOURCES ${PROJECT_SOURCE_DIR}/../vendor/pugixml/pugixml.hpp)
endif ()

if(DEMO)
    add_library(debuggerui STATIC ${SOURCES})
else()
    add_library(debuggerui SHARED ${SOURCES})
endif()

if(BN_INTERNAL_BUILD)
    ui_plugin_rpath(debuggerui)
    set_target_properties(debuggerui PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
            RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
else()
    set_target_properties(debuggerui PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/plugins
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/plugins
            )
endif()

set_target_properties(debuggerui PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
        )

target_link_libraries(debuggerui debuggerapi binaryninjaui Qt6::Core Qt6::Gui Qt6::Widgets)

if(WIN32)
    target_link_libraries(debuggerui urlmon.lib shell32.lib ole32.lib)
endif()
