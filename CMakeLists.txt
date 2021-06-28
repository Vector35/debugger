cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

option(QT6 "Target Qt 6" OFF)
option(BN_BUILD_CLI_DEBUGGER "Build CLI Debugger" OFF)

project(debugger)

if((NOT BN_API_PATH) AND (NOT BN_INTERNAL_BUILD))
	set(BN_API_PATH $ENV{BN_API_PATH})
	if(NOT BN_API_PATH)
		message(FATAL_ERROR "Provide path to Binary Ninja API source in BN_API_PATH")
	endif()
endif()
if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${BN_API_PATH} ${PROJECT_BINARY_DIR}/api)
endif()

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

if((NOT BN_API_PATH) AND (NOT BN_INTERNAL_BUILD))
	set(BN_API_PATH $ENV{BN_API_PATH})
	if(NOT BN_API_PATH)
		message(FATAL_ERROR "Provide path to Binary Ninja API source in BN_API_PATH")
	endif()
endif()
if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${BN_API_PATH} ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES
	*.cpp
	*.h
    dockwidgets/*.cpp
    dockwidgets/*.h
    adapters/*.cpp
    adapters/*.h
    src/*.cpp
	src/*.h)

list(FILTER SOURCES EXCLUDE REGEX moc_.*)
list(FILTER SOURCES EXCLUDE REGEX qrc_.*)
include_directories(src/vendor)

if(DEMO)
	add_library(debugger STATIC ${SOURCES})
else()
	add_library(debugger SHARED ${SOURCES})
endif()

if(QT6)
	target_link_libraries(debugger binaryninjaapi
		Qt6::Core Qt6::Gui Qt6::Widgets dbgeng.lib)
else()
	target_link_libraries(debugger binaryninjaapi
		Qt5::Core Qt5::Gui Qt5::Widgets dbgeng.lib)
endif()

if(BN_INTERNAL_BUILD)
    target_link_libraries(binaryninjaui)
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

# This does not work right now
bn_install_plugin(${PROJECT_NAME})

if(BN_BUILD_CLI_DEBUGGER)
	add_subdirectory(${CMAKE_SOURCE_DIR}/cli)
endif()
