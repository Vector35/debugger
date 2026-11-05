cmake_minimum_required(VERSION 3.15)

# Also usable on its own: no Binary Ninja runtime, license, Qt or LLDB required.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
	project(ptrace-engine-tests LANGUAGES C CXX)
endif()
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
	message(FATAL_ERROR "The ptrace engine tests require Linux")
endif()

find_package(Threads REQUIRED)
get_filename_component(DEBUGGER_TEST_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
set(PTRACE_ENGINE_SRC "${DEBUGGER_TEST_ROOT}/core/adapters/ptrace")
if(NOT TARGET elfio::elfio)
	add_subdirectory("${DEBUGGER_TEST_ROOT}/vendor/elfio" "${CMAKE_CURRENT_BINARY_DIR}/elfio" EXCLUDE_FROM_ALL)
endif()
if(NOT BN_API_PATH)
	if(BN_INTERNAL_BUILD)
		set(BN_API_PATH "${CMAKE_SOURCE_DIR}/api")
	else()
		set(BN_API_PATH "$ENV{BN_API_PATH}" CACHE PATH "Binary Ninja API headers")
	endif()
endif()
if(NOT EXISTS "${BN_API_PATH}/binaryninjacore.h")
	message(FATAL_ERROR "Set BN_API_PATH to the Binary Ninja API headers")
endif()
if(NOT TARGET fmt::fmt)
	add_subdirectory("${BN_API_PATH}/vendor/fmt" "${CMAKE_CURRENT_BINARY_DIR}/fmt" EXCLUDE_FROM_ALL)
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
	set(PTRACE_TEST_ARCH arm64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
	set(PTRACE_TEST_ARCH x86_64)
else()
	message(FATAL_ERROR "Unsupported ptrace test host: ${CMAKE_SYSTEM_PROCESSOR}")
endif()
set(PTRACE_TEST_CORPUS_DIR "${DEBUGGER_TEST_ROOT}/test/binaries/Linux-${PTRACE_TEST_ARCH}"
	CACHE PATH "Existing debugger test binaries for this host architecture")
set(PTRACE_TEST_SANITIZER "" CACHE STRING "Optional ptrace test instrumentation: address or thread")
set_property(CACHE PTRACE_TEST_SANITIZER PROPERTY STRINGS "" address thread)
if(NOT PTRACE_TEST_SANITIZER MATCHES "^(|address|thread)$")
	message(FATAL_ERROR "PTRACE_TEST_SANITIZER must be empty, address or thread")
endif()

add_library(ptrace_test_options INTERFACE)
target_compile_features(ptrace_test_options INTERFACE cxx_std_20)
target_include_directories(ptrace_test_options INTERFACE "${PTRACE_ENGINE_SRC}" "${BN_API_PATH}")
target_compile_definitions(ptrace_test_options INTERFACE
	PTRACE_TEST_DIRECTORY="${CMAKE_CURRENT_BINARY_DIR}"
	PTRACE_TEST_CORPUS_DIRECTORY="${PTRACE_TEST_CORPUS_DIR}")

add_library(ptrace_test_instrumentation INTERFACE)
if(PTRACE_TEST_SANITIZER)
	if(PTRACE_TEST_SANITIZER STREQUAL "address")
		set(PTRACE_SANITIZERS address,undefined)
	else()
		set(PTRACE_SANITIZERS thread)
	endif()
	target_compile_options(ptrace_test_instrumentation INTERFACE
		-O1 -g -fno-omit-frame-pointer "-fsanitize=${PTRACE_SANITIZERS}")
	target_link_options(ptrace_test_instrumentation INTERFACE "-fsanitize=${PTRACE_SANITIZERS}")
endif()

# Instrument the debugger, not its inferiors: sanitizer startup would change the
# instruction sequences and process lifecycle that these fixtures exercise.
add_library(ptrace_test_arch STATIC "${PTRACE_ENGINE_SRC}/ptracearch.cpp")
target_link_libraries(ptrace_test_arch PUBLIC ptrace_test_options ptrace_test_instrumentation)
add_library(ptrace_test_engine STATIC
	"${PTRACE_ENGINE_SRC}/ptraceengine.cpp"
	"${PTRACE_ENGINE_SRC}/ptracestep.cpp"
	"${PTRACE_ENGINE_SRC}/ptraceelf.cpp"
	"${PTRACE_ENGINE_SRC}/ptracemodule.cpp"
	"${PTRACE_ENGINE_SRC}/ptracesignal.cpp"
	"${PTRACE_ENGINE_SRC}/ptracesyscall.cpp")
target_link_libraries(ptrace_test_engine PUBLIC ptrace_test_arch Threads::Threads PRIVATE elfio::elfio fmt::fmt)

foreach(program progs progs_pad)
	add_executable(ptrace_${program} progs.c)
	target_compile_options(ptrace_${program} PRIVATE -O0 -fno-omit-frame-pointer -fno-pie)
	target_link_options(ptrace_${program} PRIVATE -no-pie)
	target_link_libraries(ptrace_${program} PRIVATE ptrace_test_options Threads::Threads ${CMAKE_DL_LIBS})
	set_target_properties(ptrace_${program} PROPERTIES OUTPUT_NAME ${program}
		RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
endforeach()
target_compile_definitions(ptrace_progs_pad PRIVATE PAD)
add_library(ptrace_libtest SHARED libtest.c)
set_target_properties(ptrace_libtest PROPERTIES OUTPUT_NAME test
	LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

set(PTRACE_TEST_PROGRAMS driver fault_driver review_driver event_exception_demo elfcmp layout hwabi)
foreach(program IN LISTS PTRACE_TEST_PROGRAMS)
	add_executable(ptrace_${program} ${program}.cpp)
	set_target_properties(ptrace_${program} PROPERTIES OUTPUT_NAME ${program}
		RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
	if(program STREQUAL "layout" OR program STREQUAL "hwabi")
		target_link_libraries(ptrace_${program} PRIVATE ptrace_test_arch)
	else()
		target_link_libraries(ptrace_${program} PRIVATE ptrace_test_engine)
	endif()
	add_dependencies(ptrace_${program} ptrace_progs ptrace_progs_pad ptrace_libtest)
endforeach()
foreach(program fault_driver review_driver)
	target_sources(ptrace_${program} PRIVATE faultwrap.cpp)
	target_link_options(ptrace_${program} PRIVATE
		-Wl,--wrap=ptrace -Wl,--wrap=pwrite -Wl,--wrap=open -Wl,--wrap=waitpid)
endforeach()

add_custom_target(ptrace_tests DEPENDS
	ptrace_driver ptrace_fault_driver ptrace_review_driver ptrace_event_exception_demo
	ptrace_elfcmp ptrace_layout ptrace_hwabi)
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/ptrace_test_config.json" CONTENT
	"{\"corpus\":\"${PTRACE_TEST_CORPUS_DIR}\",\"sanitizer\":\"${PTRACE_TEST_SANITIZER}\"}\n")
