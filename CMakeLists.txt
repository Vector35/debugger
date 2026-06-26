cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(debugger)

if((NOT BN_API_PATH) AND (NOT BN_INTERNAL_BUILD))
	set(BN_API_PATH $ENV{BN_API_PATH})
	if(NOT BN_API_PATH)
		message(FATAL_ERROR "Provide path to Binary Ninja API source in BN_API_PATH")
	endif()
endif()

if (NOT BN_INTERNAL_BUILD)
	set(QT_VERSION 6.10.1 CACHE STRING "Version of Qt to use")

	if(DEFINED ENV{QT_INSTALL_DIR})
		set(QT_INSTALL_DIR $ENV{QT_INSTALL_DIR}/${QT_VERSION})
	else()
		if(APPLE)
			set(QT_INSTALL_DIR $ENV{HOME}/Qt/${QT_VERSION})
		elseif(WIN32)
			set(QT_INSTALL_DIR $ENV{HOMEDRIVE}$ENV{HOMEPATH}/Qt/${QT_VERSION})
		else()
			set(QT_INSTALL_DIR $ENV{HOME}/Qt/${QT_VERSION})
		endif()
	endif()

	if(NOT CMAKE_PREFIX_PATH)
		set(CMAKE_PREFIX_PATH ${QT_INSTALL_DIR}/lib/cmake)
	endif()
	message("CMAKE_PREFIX_PATH is: ${CMAKE_PREFIX_PATH}")
endif()

add_subdirectory(core)
add_subdirectory(api)

if(NOT HEADLESS)
	add_subdirectory(ui)
endif()

if (NOT DEMO)
	add_subdirectory(cli)
endif()

# Build the debugger unit-test binaries alongside the debugger (on by default, for both local and CI
# builds), so adding a new test no longer requires a separate build. The binaries are staged into
# test/binaries/<OS>-<arch>; on macOS the debuggercore POST_BUILD step signs that directory into the
# -signed directory the tests load from, so make debuggercore depend on the staged binaries. On a
# universal macOS build the test binaries are still emitted thin, one per architecture. Binaries
# needing extra tooling (e.g. the nasm assembly samples) remain pre-built by the debugger-test-binaries CI.
option(BUILD_DEBUGGER_TEST_BINARIES "Build the debugger unit-test binaries alongside the debugger" ON)
if (BUILD_DEBUGGER_TEST_BINARIES)
	add_subdirectory(test)
	if (APPLE AND TARGET debuggercore)
		add_dependencies(debuggercore debugger_test_binaries)
	endif()
endif()

# WinDbg installer CLI (standalone, spawned by debuggercore API)
if(WIN32)
	add_subdirectory(installer)
endif()

# Documentation validation target
add_custom_target(docs-validate
	COMMAND python ${CMAKE_SOURCE_DIR}/scripts/check_markdown_list.py ${CMAKE_SOURCE_DIR}/docs/
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	COMMENT "Validating documentation formatting..."
)
