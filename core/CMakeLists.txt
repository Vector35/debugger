cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(debuggercore)

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
    *.cpp
    *.h
    ../vendor/pugixml/*.cpp
    ../vendor/pugixml/*.hpp
    ../vendor/fmt/*.h
    )

file(GLOB ADAPTER_SOURCES
		adapters/lldbrspadapter.cpp
		adapters/lldbrspadapter.h
		adapters/gdbadapter.cpp
		adapters/gdbadapter.h
		adapters/queuedadapter.cpp
		adapters/queuedadapter.h
		adapters/rspconnector.cpp
		adapters/rspconnector.h
		adapters/socket.h
	)

if(WIN32)
	set(SOURCES ${COMMON_SOURCES} ${ADAPTER_SOURCES} adapters/dbgengadapter.cpp adapters/dbgengadapter.h)
else()
	set(SOURCES ${COMMON_SOURCES} ${ADAPTER_SOURCES})
endif()

if(DEMO)
	add_library(debuggercore STATIC ${SOURCES})
else()
	add_library(debuggercore SHARED ${SOURCES})
endif()

target_link_libraries(debuggercore binaryninjaapi)

if(WIN32)
    target_link_libraries(debuggercore dbgeng.lib wsock32 ws2_32)
endif()

set_target_properties(debuggercore PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON
	SOVERSION 1
)

if(BN_INTERNAL_BUILD)
	set_target_properties(debuggercore PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
else()
    set_target_properties(debuggercore PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out
        )
endif()

# This does not work right now
bn_install_plugin(${PROJECT_NAME})

include_directories(../vendor)

target_compile_definitions(debuggercore PRIVATE DEBUGGER_LIBRARY)

if(BN_INTERNAL_BUILD)
	add_custom_command(TARGET debuggercore POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_SOURCE_DIR}/adapters/gdb ${BN_CORE_PLUGIN_DIR}/gdb)
endif()