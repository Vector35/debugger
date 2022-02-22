cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

option(BN_BUILD_CLI_DEBUGGER "Build CLI Debugger" ON)

project(debugger)
add_definitions(-DFMT_HEADER_ONLY)

if((NOT BN_API_PATH) AND (NOT BN_INTERNAL_BUILD))
	set(BN_API_PATH $ENV{BN_API_PATH})
	if(NOT BN_API_PATH)
		message(FATAL_ERROR "Provide path to Binary Ninja API source in BN_API_PATH")
	endif()
endif()
if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${BN_API_PATH} ${PROJECT_BINARY_DIR}/api)
endif()

add_subdirectory(core)
add_subdirectory(api)
if(NOT HEADLESS)
	add_subdirectory(ui)
endif()

if(BN_BUILD_CLI_DEBUGGER)
	add_subdirectory(cli)
endif()
