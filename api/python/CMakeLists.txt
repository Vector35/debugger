cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(debugger-python-api)

file(GLOB PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/*.py)
list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/_debuggercore.py)
list(REMOVE_ITEM PYTHON_SOURCES ${PROJECT_SOURCE_DIR}/enums.py)

add_executable(debugger_generator
	${PROJECT_SOURCE_DIR}/generator.cpp)
target_link_libraries(debugger_generator binaryninjaapi)

set_target_properties(debugger_generator PROPERTIES
    CXX_STANDARD 17
	CXX_STANDARD_REQUIRED ON
	BUILD_WITH_INSTALL_RPATH OFF
	RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

if(BN_INTERNAL_BUILD)
	set(PYTHON_OUTPUT_DIRECTORY ${BN_RESOURCE_DIR}/python/binaryninja/debugger/)
else()
	set(PYTHON_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/plugins/debugger/)
endif()

if(WIN32)
	if (BN_INTERNAL_BUILD)
		add_custom_command(TARGET debugger_generator PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy ${BN_CORE_OUTPUT_DIR}/binaryninjacore.dll ${PROJECT_BINARY_DIR}/)
	else()
		add_custom_command(TARGET debugger_generator PRE_BUILD
				COMMAND ${CMAKE_COMMAND} -E copy ${BN_INSTALL_DIR}/binaryninjacore.dll ${PROJECT_BINARY_DIR}/)
	endif()
endif()

add_custom_target(debugger_generator_copy ALL
	BYPRODUCTS ${PROJECT_SOURCE_DIR}/_debuggercore.py ${PROJECT_SOURCE_DIR}/enums.py
	DEPENDS ${PYTHON_SOURCES} ${PROJECT_SOURCE_DIR}/../ffi.h $<TARGET_FILE:debugger_generator>
	COMMAND ${CMAKE_COMMAND} -E echo "Copying Debugger Python Sources"
	COMMAND ${CMAKE_COMMAND} -E make_directory ${PYTHON_OUTPUT_DIRECTORY}
	COMMAND ${CMAKE_COMMAND} -E env ASAN_OPTIONS=detect_leaks=0 $<TARGET_FILE:debugger_generator>
		${PROJECT_SOURCE_DIR}/../ffi.h
		${PROJECT_SOURCE_DIR}/_debuggercore.py
		${PROJECT_SOURCE_DIR}/_debuggercore_template.py
		${PROJECT_SOURCE_DIR}/debugger_enums.py

	COMMAND ${CMAKE_COMMAND} -E copy ${PYTHON_SOURCES} ${PYTHON_OUTPUT_DIRECTORY}
	COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/_debuggercore.py ${PYTHON_OUTPUT_DIRECTORY}
	COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/debugger_enums.py ${PYTHON_OUTPUT_DIRECTORY})

