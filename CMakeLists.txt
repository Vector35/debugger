cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(debugger)

if((NOT BN_API_PATH) AND (NOT BN_INTERNAL_BUILD))
	set(BN_API_PATH $ENV{BN_API_PATH})
	if(NOT BN_API_PATH)
		message(FATAL_ERROR "Provide path to Binary Ninja API source in BN_API_PATH")
	endif()
endif()

if (NOT BN_INTERNAL_BUILD)
	set(QT_VERSION 6.11.1 CACHE STRING "Version of Qt to use")

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

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# FlatBuffers is used for the x2win RPC protocol. Its C++ runtime is header-only (see
# FlatBuffers_Library_SRCS in vendor/flatbuffers/CMakeLists.txt -- every entry is a .h, no .cpp),
# so unlike Protobuf/Abseil (formerly vendored here for the same protocol, since removed) there's
# no compiled static lib whose CRT/ABI settings need to match whatever links against it -- only
# flatc (the schema compiler) is an actual build-time binary. That's what let x2winstub drop its
# MSVC-ABI-pinned toolchain requirement for MinGW-w64 once the protocol finished migrating over.
# flatbuffers_generate_headers() (used by core/CMakeLists.txt and x2winstub/CMakeLists.txt) comes
# from vendor/flatbuffers/CMake/BuildFlatBuffers.cmake, which flatbuffers' own CMakeLists.txt
# already include()s, so no separate include() is needed here the way protobuf-generate.cmake was.
set(FLATBUFFERS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(FLATBUFFERS_INSTALL OFF CACHE BOOL "" FORCE)
set(FLATBUFFERS_BUILD_FLATC ON CACHE BOOL "" FORCE)
add_subdirectory(vendor/flatbuffers)

# Generated once here and shared via target_link_libraries(... x2win_fbs) from both
# core/CMakeLists.txt and x2winstub/CMakeLists.txt, rather than calling
# flatbuffers_generate_headers() separately from each (which would define two CMake targets
# both named "x2win_fbs" and fail to configure -- target names must be unique project-wide).
flatbuffers_generate_headers(
    TARGET x2win_fbs
    SCHEMAS ${CMAKE_SOURCE_DIR}/protocol/x2win.fbs
)

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
	add_subdirectory(x2winstub)
endif()

# Documentation validation target
add_custom_target(docs-validate
	COMMAND python ${CMAKE_SOURCE_DIR}/scripts/check_markdown_list.py ${CMAKE_SOURCE_DIR}/docs/
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	COMMENT "Validating documentation formatting..."
)
