cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

# This project builds the test binaries for the debugger unit test. It does not run the test.
project(debugger-test-binaries C CXX)

add_executable(helloworld src/helloworld.c)
set_target_properties(helloworld PROPERTIES
		POSITION_INDEPENDENT_CODE OFF
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

add_executable(exitcode src/exitcode.c)
set_target_properties(exitcode PROPERTIES
		POSITION_INDEPENDENT_CODE OFF
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

add_executable(helloworld_thread src/helloworld_thread.c)
set_target_properties(helloworld_thread PROPERTIES
		POSITION_INDEPENDENT_CODE OFF
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

add_executable(helloworld_loop src/helloworld_loop.c)
set_target_properties(helloworld_loop PROPERTIES
		POSITION_INDEPENDENT_CODE OFF
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

add_executable(helloworld_func src/helloworld_func.c)
set_target_properties(helloworld_func PROPERTIES
		POSITION_INDEPENDENT_CODE OFF
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

add_executable(helloworld_recursion src/helloworld_recursion.c)
set_target_properties(helloworld_recursion PROPERTIES
		POSITION_INDEPENDENT_CODE OFF
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

add_executable(helloworld_pie src/helloworld.c)
set_target_properties(helloworld_pie PROPERTIES
		POSITION_INDEPENDENT_CODE ON
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

add_executable(helloworld_thread_pie src/helloworld_thread.c)
set_target_properties(helloworld_thread_pie PROPERTIES
		POSITION_INDEPENDENT_CODE ON
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

add_executable(helloworld_loop_pie src/helloworld_loop.c)
set_target_properties(helloworld_loop_pie PROPERTIES
		POSITION_INDEPENDENT_CODE ON
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

add_executable(helloworld_func_pie src/helloworld_func.c)
set_target_properties(helloworld_func_pie PROPERTIES
		POSITION_INDEPENDENT_CODE ON
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

add_executable(helloworld_recursion_pie src/helloworld_recursion.c)
set_target_properties(helloworld_recursion_pie PROPERTIES
		POSITION_INDEPENDENT_CODE ON
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

if(APPLE)
	add_executable(helloworld_objc src/helloworld_objc.m)
	set_target_properties(helloworld_objc PROPERTIES
			POSITION_INDEPENDENT_CODE OFF
			RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
			)
	target_link_libraries(helloworld_objc
			"-framework AppKit"
			"-framework Carbon"
			"-framework Foundation")
endif()

add_executable(helloworld_virtual src/helloworld_virtual.cpp)
set_target_properties(helloworld_virtual PROPERTIES
		POSITION_INDEPENDENT_CODE OFF
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

add_executable(many_stdlib_calls src/many_stdlib_calls.c)
set_target_properties(many_stdlib_calls PROPERTIES
		POSITION_INDEPENDENT_CODE OFF
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)



# ASM files

enable_language(ASM_NASM)
# This flag is used to generate different assembly instruction on different OS
if(APPLE)
	set(CMAKE_ASM_NASM_FLAGS "-DOS_IS_MACOS")
elseif(WIN32)
	set(CMAKE_ASM_NASM_FLAGS "-DOS_IS_WINDOWS")
else()
	set(CMAKE_ASM_NASM_FLAGS "-DOS_IS_LINUX")
endif(APPLE)

if (APPLE)
	set(CMAKE_NASM_LINK_EXECUTABLE "ld <LINK_FLAGS> -macosx_version_min 10.7.0 -L/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")
else()
	set(CMAKE_NASM_LINK_EXECUTABLE "ld <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")
endif()

add_executable(asmtest src/asmtest_x64.asm)
if (APPLE)
	target_link_libraries(asmtest System)
endif (APPLE)
set_target_properties(asmtest PROPERTIES
		POSITION_INDEPENDENT_CODE OFF
		LINKER_LANGUAGE NASM
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)


add_executable(hello src/hello_x64.asm)
if (APPLE)
	target_link_libraries(hello System)
endif (APPLE)
set_target_properties(hello PROPERTIES
		POSITION_INDEPENDENT_CODE OFF
		LINKER_LANGUAGE NASM
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

add_executable(analysis_propagation src/analysis_propagation_x64.asm)
if (APPLE)
	target_link_libraries(analysis_propagation System)
endif (APPLE)
set_target_properties(analysis_propagation PROPERTIES
		POSITION_INDEPENDENT_CODE OFF
		LINKER_LANGUAGE NASM
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)
add_custom_command(TARGET analysis_propagation POST_BUILD
		COMMAND strip "$<TARGET_FILE:analysis_propagation>"
		COMMAND python3 src/rm_func_starts.py "$<TARGET_FILE:analysis_propagation>")

add_executable(indirect_calls src/indirect_calls_x64.asm)
if (APPLE)
	target_link_libraries(indirect_calls System)
endif (APPLE)
set_target_properties(indirect_calls PROPERTIES
		POSITION_INDEPENDENT_CODE OFF
		LINKER_LANGUAGE NASM
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)
add_custom_command(TARGET indirect_calls POST_BUILD
		COMMAND strip "$<TARGET_FILE:indirect_calls>"
		COMMAND python3 src/rm_func_starts.py "$<TARGET_FILE:indirect_calls>")


if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64" OR ${CMAKE_SYSTEM_PROCESSOR} STREQUAL "AMD64")
	add_definitions(-DARCH_IS_X64)
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm64")
	add_definitions(-DARCH_IS_AARCH64)
endif()
add_executable(do_exception src/do_exception.c)
set_target_properties(do_exception PROPERTIES
		POSITION_INDEPENDENT_CODE OFF
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

add_executable(nopspeed src/nopspeed.c)
set_target_properties(nopspeed PROPERTIES
		POSITION_INDEPENDENT_CODE ON
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

add_executable(cat src/cat.c)
set_target_properties(cat PROPERTIES
		POSITION_INDEPENDENT_CODE ON
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

add_executable(commandline_test src/commandline_test.c)
set_target_properties(commandline_test PROPERTIES
		POSITION_INDEPENDENT_CODE ON
		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
		)

# This must be put at the end because it changes the CMAKE_OSX_ARCHITECTURES and does not change it back
#set(CMAKE_OSX_ARCHITECTURES "i386")
#add_executable(helloworld_i386 src/helloworld.c)
#set_target_properties(helloworld_i386 PROPERTIES
#		POSITION_INDEPENDENT_CODE ON
#		RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/binaries/${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}
#		)
