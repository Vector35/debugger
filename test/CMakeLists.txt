cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

# Builds debugger unit-test binaries alongside the debugger so that adding a new test does not
# require a separate build. Enabled by default from the top-level build (BUILD_DEBUGGER_TEST_BINARIES)
# and thus built by both local and CI debugger builds. It only builds binaries the host toolchain can
# produce; binaries needing extra tooling (e.g. the nasm assembly samples) remain pre-built by CI.
#
# The binaries are staged into this source tree under binaries/<OS>-<arch>, alongside the committed
# test binaries. On macOS the debuggercore POST_BUILD step (see ../core/CMakeLists.txt) codesigns
# that directory into binaries/<OS>-<arch>-signed, which is where the tests load from; the top-level
# build makes debuggercore depend on these targets so they are staged before that signing runs. These
# staged binaries are not committed (see ../.gitignore).
project(debugger-test-binaries C CXX)

# An ARCH may be passed explicitly (e.g. -DARCH=arm64); otherwise default to the host architecture.
if (NOT ARCH)
	if (CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64|ARM64")
		set(ARCH arm64)
	elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
		set(ARCH x86_64)
	elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i686|x86")
		set(ARCH x86)
	else()
		message(FATAL_ERROR "Could not determine ARCH from CMAKE_SYSTEM_PROCESSOR='${CMAKE_SYSTEM_PROCESSOR}'; pass -DARCH=...")
	endif()
	message(STATUS "ARCH not specified, defaulting to host architecture: ${ARCH}")
endif()

# Which architectures to build. On macOS, honor a universal parent build (CMAKE_OSX_ARCHITECTURES,
# e.g. "arm64;x86_64" in CI) by producing a separate thin binary per architecture instead of one
# universal binary; otherwise build the single ARCH.
if (APPLE AND CMAKE_OSX_ARCHITECTURES)
	set(TEST_BINARY_ARCHES ${CMAKE_OSX_ARCHITECTURES})
else()
	set(TEST_BINARY_ARCHES ${ARCH})
endif()

set(TEST_BINARY_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/binaries)

# Aggregate target the top-level build can depend on to ensure these are staged before signing.
add_custom_target(debugger_test_binaries)

# A shared library and an executable that loads it, built thin for a single architecture. The
# debugger tests analyze the shared library but set the executable path to the loader, exercising the
# fix for https://github.com/Vector35/debugger/issues/1104 (see issue #540 for the broader scenario).
# The library is emitted without the "lib" prefix so the tests can refer to it as shared_lib.{dylib,so,dll}.
function(add_test_binaries arch)
	set(archdir ${CMAKE_CURRENT_BINARY_DIR}/${arch})
	set(dest ${TEST_BINARY_ROOT}/${CMAKE_SYSTEM_NAME}-${arch})

	add_library(shared_lib_${arch} SHARED src/shared_lib.c)
	set_target_properties(shared_lib_${arch} PROPERTIES
			OUTPUT_NAME shared_lib
			PREFIX ""
			POSITION_INDEPENDENT_CODE ON
			LIBRARY_OUTPUT_DIRECTORY ${archdir}
			RUNTIME_OUTPUT_DIRECTORY ${archdir}
			)

	add_executable(load_shared_lib_${arch} src/load_shared_lib.c)
	target_link_libraries(load_shared_lib_${arch} shared_lib_${arch})
	set_target_properties(load_shared_lib_${arch} PROPERTIES
			OUTPUT_NAME load_shared_lib
			POSITION_INDEPENDENT_CODE ON
			RUNTIME_OUTPUT_DIRECTORY ${archdir}
			)

	if (APPLE)
		# Build this pair thin for ${arch} even inside a universal parent build.
		set_target_properties(shared_lib_${arch} load_shared_lib_${arch} PROPERTIES OSX_ARCHITECTURES ${arch})
		# Record the install name relative to the loader so the executable finds the library when both
		# sit in the same binaries directory, regardless of where that directory ends up.
		set_target_properties(shared_lib_${arch} PROPERTIES
				INSTALL_NAME_DIR "@loader_path"
				BUILD_WITH_INSTALL_NAME_DIR ON
				)
	elseif (UNIX)
		# Resolve the library next to the executable at runtime.
		set_target_properties(load_shared_lib_${arch} PROPERTIES
				BUILD_RPATH "$ORIGIN"
				INSTALL_RPATH "$ORIGIN"
				)
	endif()

	# Stage both into the (unsigned) binaries/<OS>-<arch> directory the tests / signing step read from.
	foreach (tgt shared_lib_${arch} load_shared_lib_${arch})
		add_custom_command(TARGET ${tgt} POST_BUILD
				COMMAND ${CMAKE_COMMAND} -E make_directory ${dest}
				COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${tgt}> ${dest}/
				COMMENT "Staging ${tgt} -> ${dest}"
				VERBATIM)
		add_dependencies(debugger_test_binaries ${tgt})
	endforeach()
endfunction()

foreach (arch ${TEST_BINARY_ARCHES})
	add_test_binaries(${arch})
endforeach()
