cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

option(BN_BUILD_CLI_DEBUGGER "Build CLI Debugger" ON)

project(debugger)
add_definitions(-DFMT_HEADER_ONLY)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

if((NOT BN_API_PATH) AND (NOT BN_INTERNAL_BUILD))
	set(BN_API_PATH $ENV{BN_API_PATH})
	if(NOT BN_API_PATH)
		message(FATAL_ERROR "Provide path to Binary Ninja API source in BN_API_PATH")
	endif()
endif()
if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${BN_API_PATH} ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB COMMON_SOURCES
    src/*.cpp
    src/*.h
    src/ui/*.cpp
    src/ui/*.h
    src/vendor/pugixml/*.cpp
    src/vendor/pugixml/*.hpp
    src/vendor/fmt/*.h
    )

if(WIN32)
    file(GLOB ADAPTER_SOURCES
        src/adapters/dbgengadapter.cpp
        src/adapters/dbgengadapter.h
		src/adapters/gdbadapter.cpp
		src/adapters/gdbadapter.h
		src/adapters/rspconnector.cpp
		src/adapters/rspconnector.h
		src/adapters/queuedadapter.cpp
		src/adapters/queuedadapter.h
		src/adapters/socket.h
			)
elseif(APPLE)
	file(GLOB ADAPTER_SOURCES
			src/adapters/lldbadapter.cpp
			src/adapters/lldbadapter.h
			src/adapters/gdbadapter.cpp
			src/adapters/gdbadapter.h
			src/adapters/queuedadapter.cpp
			src/adapters/queuedadapter.h
			src/adapters/rspconnector.cpp
			src/adapters/rspconnector.h
			)
else()
    file(GLOB ADAPTER_SOURCES
        src/adapters/gdbadapter.cpp
        src/adapters/gdbadapter.h
		src/adapters/lldbadapter.cpp
		src/adapters/lldbadapter.h
		src/adapters/queuedadapter.cpp
		src/adapters/queuedadapter.h
        src/adapters/rspconnector.cpp
        src/adapters/rspconnector.h
        )
endif()

set(SOURCES ${COMMON_SOURCES} ${ADAPTER_SOURCES})

list(FILTER SOURCES EXCLUDE REGEX moc_.*)
list(FILTER SOURCES EXCLUDE REGEX qrc_.*)
include_directories(src/vendor)

if(DEMO)
	add_library(debugger STATIC ${SOURCES})
else()
	add_library(debugger SHARED ${SOURCES})
endif()

target_link_libraries(debugger binaryninjaapi binaryninjaui
    Qt6::Core Qt6::Gui Qt6::Widgets)

if(WIN32)
    target_link_libraries(debugger dbgeng.lib wsock32 ws2_32)
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
else()
    set_target_properties(debugger PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out
        )
endif()

# This does not work right now
bn_install_plugin(${PROJECT_NAME})

#if(BN_BUILD_CLI_DEBUGGER)
#	add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/cli)
#endif()
