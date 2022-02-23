cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

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

add_subdirectory(cli)

if(WIN32)
	add_custom_target(test_debugger
			COMMAND ${CMAKE_COMMAND} -E env PYTHONPATH=${BN_RESOURCE_DIR}/python py -3 test/unit.py
			WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
else()
	add_custom_target(test_debugger
			COMMAND ${CMAKE_COMMAND} -E env PYTHONPATH=${BN_RESOURCE_DIR}/python python3 test/unit.py
			WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endif()