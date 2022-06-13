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
		adapters/lldbadapter.cpp
		adapters/lldbadapter.h
#		adapters/lldbrspadapter.cpp
#		adapters/lldbrspadapter.h
#		adapters/gdbadapter.cpp
#		adapters/gdbadapter.h
#		adapters/queuedadapter.cpp
#		adapters/queuedadapter.h
#		adapters/rspconnector.cpp
#		adapters/rspconnector.h
#		adapters/socket.h
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
    target_link_libraries(debuggercore Msi.lib delayimp.lib wsock32 ws2_32)
	target_link_options(debuggercore PRIVATE /DELAYLOAD:liblldb.dll)
endif()

set_target_properties(debuggercore PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON
)

if(BN_INTERNAL_BUILD)
	set(LIBRARY_OUTPUT_DIRECTORY_PATH "${BN_CORE_PLUGIN_DIR}")
else()
	set(LIBRARY_OUTPUT_DIRECTORY_PATH "${CMAKE_BINARY_DIR}/out/plugins")
endif()

set_target_properties(debuggercore PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${LIBRARY_OUTPUT_DIRECTORY_PATH}
		RUNTIME_OUTPUT_DIRECTORY ${LIBRARY_OUTPUT_DIRECTORY_PATH}
		)

# This does not work right now
#bn_install_plugin(${PROJECT_NAME})

target_compile_definitions(debuggercore PRIVATE DEBUGGER_LIBRARY)

if(BN_INTERNAL_BUILD)
	add_custom_command(TARGET debuggercore POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_SOURCE_DIR}/adapters/gdb ${BN_RESOURCE_DIR}/gdb)
endif()

if(DEFINED ENV{LLDB_PATH})
	set(LLDB_PATH $ENV{LLDB_PATH})
endif()

if(NOT LLDB_PATH)
	if(DEFINED LLVM_PATH)
		set(LLDB_PATH ${LLVM_PATH})
	else()
		set(LLVM_VERSION 14.0.0 CACHE STRING "Version of LLVM to use")
		if(DEFINED ENV{LLVM_INSTALL_DIR})
			set(LLDB_PATH $ENV{LLVM_INSTALL_DIR}/${LLVM_VERSION})
		elseif(WIN32)
			set(LLDB_PATH $ENV{HOMEDRIVE}$ENV{HOMEPATH}/libclang/${LLVM_VERSION})
		else()
			set(LLDB_PATH $ENV{HOME}/libclang/${LLVM_VERSION})
		endif()
	endif()
endif()
message(STATUS "lldb: using install at ${LLDB_PATH}")

if (APPLE)
	find_library(lib_lldb NAMES lldb PATHS ${LLDB_PATH}/lib REQUIRED)
	target_link_libraries(debuggercore ${lib_lldb})
	target_include_directories(debuggercore PRIVATE ${LLDB_PATH}/include)
#	This is weird. The BUILD_RPATH must be set for local builds to have the proper rpath;
#	The INSTALL_RPATH must be set for the build server builds to have the proper rpath.
	set_property(TARGET debuggercore APPEND PROPERTY BUILD_RPATH "@loader_path/lldb/lib")
	set_property(TARGET debuggercore APPEND PROPERTY INSTALL_RPATH "@loader_path/lldb/lib")
	set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
	set(MACOSX_RPATH TRUE)
#	The way we extract the lldb-build artifact zip file causes files to lose executable permissions.
#	Here, we add it back directly.
	file(
		COPY ${LLDB_PATH}/bin/lldb
		DESTINATION ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/bin
		FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
	file(
		COPY ${LLDB_PATH}/bin/lldb-server
		DESTINATION ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/bin
		FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
	file(
		COPY ${LLDB_PATH}/bin/debugserver
		DESTINATION ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/bin
		FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
	file(
		COPY ${LLDB_PATH}/bin/lldb-argdumper
		DESTINATION ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/bin
		FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
	file(
		COPY ${LLDB_PATH}/lib/liblldb.14.0.0.dylib
		DESTINATION ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/lib
		FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
elseif (UNIX)
	find_library(lib_lldb NAMES lldb PATHS ${LLDB_PATH}/lib REQUIRED)
	target_link_libraries(debuggercore ${lib_lldb})
	target_include_directories(debuggercore PRIVATE ${LLDB_PATH}/include)
	set_property(TARGET debuggercore APPEND PROPERTY BUILD_RPATH "\$ORIGIN/lldb/lib")
	set_property(TARGET debuggercore APPEND PROPERTY INSTALL_RPATH "\$ORIGIN/lldb/lib")
	set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
	file(
		COPY ${LLDB_PATH}/bin/lldb
		DESTINATION ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/bin
		FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
	file(
		COPY ${LLDB_PATH}/bin/lldb-server
		DESTINATION ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/bin
		FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
	file(
		COPY ${LLDB_PATH}/bin/lldb-argdumper
		DESTINATION ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/bin
		FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
	file(
		COPY ${LLDB_PATH}/lib/liblldb.so.14
		DESTINATION ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/lib
		FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
else()
	find_library(lib_lldb NAMES liblldb PATHS ${LLDB_PATH}/lib REQUIRED)
	target_link_libraries(debuggercore ${lib_lldb})
	target_include_directories(debuggercore PRIVATE ${LLDB_PATH}/include)
	if(NOT DEMO)
		add_custom_command(TARGET debuggercore PRE_LINK
				COMMAND ${CMAKE_COMMAND} -E echo "Copying LLDB Libs"
				COMMAND ${CMAKE_COMMAND} -E make_directory ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb
				COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb.exe ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb
				COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb-server.exe ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb
				COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb-argdumper.exe ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb
				COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/liblldb.dll ${LIBRARY_OUTPUT_DIRECTORY_PATH}
				)
	else()
		# On Windows, there is no rpath, so we must put the liblldb.dll in the same folder as binaryninja.exe.
		# This is NOT needed for non-demo builds, because the debuggercore and the liblldb.dll are both in the
		# plugins folder.
		add_custom_command(TARGET debuggercore PRE_LINK
				COMMAND ${CMAKE_COMMAND} -E echo "Copying LLDB Libs"
				COMMAND ${CMAKE_COMMAND} -E make_directory ${BN_CORE_OUTPUT_DIR}/lldb
				COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb.exe ${BN_CORE_OUTPUT_DIR}/lldb
				COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb-server.exe ${BN_BINARY_DIR}/lldb
				COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb-argdumper.exe ${BN_CORE_OUTPUT_DIR}/lldb
				COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/liblldb.dll ${BN_CORE_OUTPUT_DIR}
				)
	endif()
endif()

if (WIN32)
	if(NOT DEMO)
		add_custom_command(TARGET debuggercore PRE_LINK
				COMMAND ${CMAKE_COMMAND} -E echo "Copying DbgEng Redistributable"
				COMMAND ${CMAKE_COMMAND} -E make_directory ${LIBRARY_OUTPUT_DIRECTORY_PATH}/dbgeng
				COMMAND ${CMAKE_COMMAND} -E copy "${PROJECT_SOURCE_DIR}/adapters/dbgeng/X64 Debuggers And Tools-x64_en-us.msi"
													${LIBRARY_OUTPUT_DIRECTORY_PATH}/dbgeng
				COMMAND ${CMAKE_COMMAND} -E copy "${PROJECT_SOURCE_DIR}/adapters/dbgeng/X86 Debuggers And Tools-x86_en-us.msi"
													${LIBRARY_OUTPUT_DIRECTORY_PATH}/dbgeng
				)
	else()
		add_custom_command(TARGET debuggercore PRE_LINK
				COMMAND ${CMAKE_COMMAND} -E echo "Copying DbgEng Redistributable"
				COMMAND ${CMAKE_COMMAND} -E make_directory ${BN_CORE_OUTPUT_DIR}/dbgeng
				COMMAND ${CMAKE_COMMAND} -E copy "${PROJECT_SOURCE_DIR}/adapters/dbgeng/X64 Debuggers And Tools-x64_en-us.msi"
													${BN_CORE_OUTPUT_DIR}/dbgeng
				COMMAND ${CMAKE_COMMAND} -E copy "${PROJECT_SOURCE_DIR}/adapters/dbgeng/X64 Debuggers And Tools-x64_en-us.msi"
													${BN_BINARY_DIR}/dbgeng
				)
	endif()
endif()

if(APPLE)
	add_custom_command(TARGET debuggercore POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_SOURCE_DIR}/../test/binaries/Darwin-arm64 ${PROJECT_SOURCE_DIR}/../test/binaries/Darwin-arm64-signed
		COMMAND chmod +x ${PROJECT_SOURCE_DIR}/../test/binaries/Darwin-arm64-signed/*
		COMMAND codesign --deep --options runtime --entitlements ${PROJECT_SOURCE_DIR}/../test/entitlements.plist -s - ${PROJECT_SOURCE_DIR}/../test/binaries/Darwin-arm64-signed/*

		COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_SOURCE_DIR}/../test/binaries/Darwin-x86_64 ${PROJECT_SOURCE_DIR}/../test/binaries/Darwin-x86_64-signed
		COMMAND chmod +x ${PROJECT_SOURCE_DIR}/../test/binaries/Darwin-x86_64-signed/*
		COMMAND codesign --deep --options runtime --entitlements ${PROJECT_SOURCE_DIR}/../test/entitlements.plist -s - ${PROJECT_SOURCE_DIR}/../test/binaries/Darwin-x86_64-signed/*
		)
endif()
