cmake_minimum_required(VERSION 3.21 FATAL_ERROR)

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

file(GLOB COMMON_SOURCES CONFIGURE_DEPENDS
    *.cpp
    *.h
    ../vendor/pugixml/*.cpp
    ../vendor/pugixml/*.hpp
    ../vendor/fmt/*.h
	../vendor/intx/intx.hpp
    )

file(GLOB ADAPTER_SOURCES CONFIGURE_DEPENDS
		adapters/lldbadapter.cpp
		adapters/lldbadapter.h
		adapters/gdbadapter.cpp
		adapters/gdbadapter.h
		adapters/rspconnector.cpp
		adapters/rspconnector.h
		adapters/corelliumadapter.cpp
		adapters/corelliumadapter.h
		adapters/esrevenadapter.cpp
		adapters/esrevenadapter.h
		adapters/lldbcoredumpadapter.cpp
		adapters/lldbcoredumpadapter.h
	)

if(WIN32)
	set(SOURCES ${COMMON_SOURCES} ${ADAPTER_SOURCES}
			adapters/dbgengadapter.cpp
			adapters/dbgengadapter.h
			adapters/dbgengttdadapter.cpp
			adapters/dbgengttdadapter.h
			adapters/windowskerneladapter.cpp
			adapters/windowskerneladapter.h
			adapters/localwindowskerneladapter.cpp
			adapters/localwindowskerneladapter.h
			adapters/windowsdumpfile.cpp
			adapters/windowsdumpfile.h
			)
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
    CXX_STANDARD 20
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

if(DEFINED ENV{LLDB_PATH})
	set(LLDB_PATH $ENV{LLDB_PATH})
endif()

if(NOT LLDB_PATH)
	if(DEFINED LLVM_PATH)
		set(LLDB_PATH ${LLVM_PATH})
	else()
		set(LLVM_VERSION 19.1.7 CACHE STRING "Version of LLVM to use")
		if(ASAN)
			# Require asan clang to prevent spurious use-after-poison reports
			set(LLVM_VERSION_DIR "${LLVM_VERSION}-asan")
		else()
			set(LLVM_VERSION_DIR "${LLVM_VERSION}")
		endif()
		if(DEFINED ENV{LLVM_INSTALL_DIR})
			set(LLDB_PATH $ENV{LLVM_INSTALL_DIR}/${LLVM_VERSION_DIR})
		elseif(WIN32)
			set(LLDB_PATH $ENV{HOMEDRIVE}$ENV{HOMEPATH}/libclang/${LLVM_VERSION_DIR})
		else()
			set(LLDB_PATH $ENV{HOME}/libclang/${LLVM_VERSION_DIR})
		endif()
	endif()
endif()
message(STATUS "lldb: using install at ${LLDB_PATH}")

if (APPLE)
	find_library(lib_lldb NAMES lldb.${LLVM_VERSION} lldb PATHS ${LLDB_PATH}/lib REQUIRED NO_DEFAULT_PATH)
	target_link_libraries(debuggercore ${lib_lldb})
	target_include_directories(debuggercore PRIVATE ${LLDB_PATH}/include)
	set_property(TARGET debuggercore APPEND PROPERTY INSTALL_RPATH "@loader_path/lldb/lib")
	set_target_properties(debuggercore PROPERTIES
		BUILD_WITH_INSTALL_RPATH TRUE)
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
		COPY ${LLDB_PATH}/bin/darwin-debug
		DESTINATION ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/bin
		FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
	file(
		COPY ${LLDB_PATH}/lib/liblldb.${LLVM_VERSION}.dylib
		DESTINATION ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/lib
		FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
elseif (UNIX)
	string(REGEX MATCH "^[0-9]+\.[0-9]+" LLVM_VERSION_MAJOR_MINOR ${LLVM_VERSION})
	if(NOT EXISTS ${LLDB_PATH}/lib/liblldb.so.${LLVM_VERSION_MAJOR_MINOR})
		file(
			COPY_FILE
				${LLDB_PATH}/lib/liblldb.so.${LLVM_VERSION}
				${LLDB_PATH}/lib/liblldb.so.${LLVM_VERSION_MAJOR_MINOR}
		)
	endif()
	find_library(lib_lldb NAMES liblldb.so.${LLVM_VERSION_MAJOR_MINOR} lldb PATHS ${LLDB_PATH}/lib REQUIRED NO_DEFAULT_PATH)
	target_link_libraries(debuggercore ${lib_lldb})
	target_include_directories(debuggercore PRIVATE ${LLDB_PATH}/include)
	set_property(TARGET debuggercore APPEND PROPERTY INSTALL_RPATH "\$ORIGIN/lldb/lib")
	set_target_properties(debuggercore PROPERTIES
		BUILD_WITH_INSTALL_RPATH TRUE)
	file(
		COPY
			${LLDB_PATH}/bin/lldb
			${LLDB_PATH}/bin/lldb-server
			${LLDB_PATH}/bin/lldb-argdumper
		DESTINATION
			${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/bin
		FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
	file(
		COPY
			${LLDB_PATH}/lib/liblldb.so.${LLVM_VERSION_MAJOR_MINOR}
		DESTINATION
			${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/lib
		FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
	
	# Handle libxml2 compatibility issues across different Linux distributions
	# On Arch Linux, libxml2.so.2 has been replaced with libxml2.so.16
	# We detect the system libxml2 and create a compatibility symlink in lldb/lib
	find_library(SYSTEM_LIBXML2
		NAMES xml2
		PATHS /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib64
		NO_DEFAULT_PATH
	)
	
	if(SYSTEM_LIBXML2)
		get_filename_component(SYSTEM_LIBXML2_REAL ${SYSTEM_LIBXML2} REALPATH)
		get_filename_component(SYSTEM_LIBXML2_NAME ${SYSTEM_LIBXML2_REAL} NAME)
		message(STATUS "Found system libxml2: ${SYSTEM_LIBXML2_REAL}")
		
		# Copy the system libxml2 to our lldb/lib directory
		file(
			COPY ${SYSTEM_LIBXML2_REAL}
			DESTINATION ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/lib
			FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
		)
		
		# Create a libxml2.so.2 symlink pointing to the actual library
		# This ensures compatibility even if LLDB was built expecting libxml2.so.2
		execute_process(
			COMMAND ${CMAKE_COMMAND} -E create_symlink
				${SYSTEM_LIBXML2_NAME}
				${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/lib/libxml2.so.2
		)
		message(STATUS "Created compatibility symlink: libxml2.so.2 -> ${SYSTEM_LIBXML2_NAME}")
	else()
		message(WARNING "Could not find system libxml2, LLDB may fail to load on some systems")
	endif()
	
	# Handle libedit/editline similarly
	find_library(SYSTEM_LIBEDIT
		NAMES edit
		PATHS /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib64
		NO_DEFAULT_PATH
	)
	
	if(SYSTEM_LIBEDIT)
		get_filename_component(SYSTEM_LIBEDIT_REAL ${SYSTEM_LIBEDIT} REALPATH)
		get_filename_component(SYSTEM_LIBEDIT_NAME ${SYSTEM_LIBEDIT_REAL} NAME)
		message(STATUS "Found system libedit: ${SYSTEM_LIBEDIT_REAL}")
		
		file(
			COPY ${SYSTEM_LIBEDIT_REAL}
			DESTINATION ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/lib
			FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
		)
		
		# Create compatibility symlinks
		execute_process(
			COMMAND ${CMAKE_COMMAND} -E create_symlink
				${SYSTEM_LIBEDIT_NAME}
				${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/lib/libedit.so.0
		)
	endif()
	
	# Also copy any pre-bundled dependencies from LLDB_PATH if they exist
	if(EXISTS ${LLDB_PATH}/lib/libxml2.so.2)
		file(
			COPY ${LLDB_PATH}/lib/libxml2.so.2
			DESTINATION ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/lib
			FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
		)
	endif()
	if(EXISTS ${LLDB_PATH}/lib/libedit.so.0)
		file(
			COPY ${LLDB_PATH}/lib/libedit.so.0
			DESTINATION ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb/lib
			FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
		)
	endif()
else()
	find_library(lib_lldb NAMES liblldb PATHS ${LLDB_PATH}/lib REQUIRED NO_DEFAULT_PATH)
	target_link_libraries(debuggercore ${lib_lldb})
	target_include_directories(debuggercore PRIVATE ${LLDB_PATH}/include)
	add_custom_command(TARGET debuggercore PRE_LINK
			COMMAND ${CMAKE_COMMAND} -E echo "Copying LLDB Libs"
			COMMAND ${CMAKE_COMMAND} -E make_directory ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb.exe ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb-server.exe ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb-argdumper.exe ${LIBRARY_OUTPUT_DIRECTORY_PATH}/lldb
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/liblldb.dll ${LIBRARY_OUTPUT_DIRECTORY_PATH}
			)
endif()

if (WIN32)
	add_custom_command(TARGET debuggercore PRE_LINK
		COMMAND ${CMAKE_COMMAND} -E echo "Copying DbgEng DLLs"
		COMMAND ${CMAKE_COMMAND} -E copy_directory
			"${PROJECT_SOURCE_DIR}/adapters/dbgeng/"
			${LIBRARY_OUTPUT_DIRECTORY_PATH}/dbgeng
		)
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
