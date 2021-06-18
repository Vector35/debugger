cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

option(QT6 "Target Qt 6" OFF)

project(debugger)

if(NOT QT6)
	set(CMAKE_OSX_ARCHITECTURES x86_64)
endif()

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
if(QT6)
	find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)
else()
	find_package(Qt5 COMPONENTS Core Gui Widgets REQUIRED)
endif()

file(GLOB SOURCES
	*.cpp
	*.h
    dockwidgets/*.cpp
    dockwidgets/*.h)

list(FILTER SOURCES EXCLUDE REGEX moc_.*)
list(FILTER SOURCES EXCLUDE REGEX qrc_.*)

if(DEMO)
	add_library(debugger STATIC ${SOURCES})
else()
	add_library(debugger SHARED ${SOURCES})
endif()

if(QT6)
	target_link_libraries(debugger binaryninjaapi binaryninjaui
		Qt6::Core Qt6::Gui Qt6::Widgets)
else()
	target_link_libraries(debugger binaryninjaapi binaryninjaui
		Qt5::Core Qt5::Gui Qt5::Widgets)
endif()

set_target_properties(debugger PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON
)

if(BN_INTERNAL_BUILD)
	ui_plugin_rpath(debugger)
	set_target_properties(debugger PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()

bn_install_plugin(${PROJECT_NAME})
