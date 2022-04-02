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
		adapters/lldbrspadapter.cpp
		adapters/lldbrspadapter.h
		adapters/gdbadapter.cpp
		adapters/gdbadapter.h
		adapters/queuedadapter.cpp
		adapters/queuedadapter.h
		adapters/rspconnector.cpp
		adapters/rspconnector.h
		adapters/socket.h
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
    target_link_libraries(debuggercore dbgeng.lib wsock32 ws2_32)
endif()

set_target_properties(debuggercore PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON
	SOVERSION 1
)

if(BN_INTERNAL_BUILD)
	set_target_properties(debuggercore PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
else()
    set_target_properties(debuggercore PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out
        )
endif()

# This does not work right now
bn_install_plugin(${PROJECT_NAME})

include_directories(../vendor)

target_compile_definitions(debuggercore PRIVATE DEBUGGER_LIBRARY)

if(BN_INTERNAL_BUILD)
	add_custom_command(TARGET debuggercore POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_SOURCE_DIR}/adapters/gdb ${BN_CORE_PLUGIN_DIR}/gdb)
endif()

if(DEFINED ENV{LLDB_PATH})
	set(LLDB_PATH $ENV{LLDB_PATH})
endif()

if(NOT LLDB_PATH)
	set(LLDB_PATH ${LLVM_PATH})
endif()
message(STATUS "lldb: using install at ${LLDB_PATH}")

if (APPLE)
	find_library(lib_lldb NAMES lldb PATHS ${LLDB_PATH}/lib REQUIRED)
	target_link_libraries(debuggercore ${lib_lldb})
	target_include_directories(debuggercore PRIVATE ${LLDB_PATH}/include)
	set_property(TARGET debuggercore APPEND PROPERTY BUILD_RPATH "\$ORIGIN/lldb/lib")
	set_property(TARGET debuggercore APPEND PROPERTY INSTALL_RPATH "\$ORIGIN/lldb/lib")
#	set(CMAKE_INSTALL_RPATH ${BN_CORE_PLUGIN_DIR}/lldb/lib)
	set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
	set(MACOSX_RPATH TRUE)
	add_custom_command(TARGET debuggercore PRE_LINK
			COMMAND ${CMAKE_COMMAND} -E echo "Copying LLDB Libs"
			COMMAND ${CMAKE_COMMAND} -E make_directory ${BN_CORE_PLUGIN_DIR}/lldb/bin
			COMMAND ${CMAKE_COMMAND} -E make_directory ${BN_CORE_PLUGIN_DIR}/lldb/lib
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb ${BN_CORE_PLUGIN_DIR}/lldb/bin
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb-server ${BN_CORE_PLUGIN_DIR}/lldb/bin
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/debugserver ${BN_CORE_PLUGIN_DIR}/lldb/bin
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb-argdumper ${BN_CORE_PLUGIN_DIR}/lldb/bin
			# It is not perfect to hardcode the 14 here; but the debugger core links to it.
			# We should find a way to make the core link to liblldb.so instead.
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/lib/liblldb.14.0.0.dylib ${BN_CORE_PLUGIN_DIR}/lldb/lib
			)
elseif (UNIX)
	find_library(lib_lldb NAMES lldb PATHS ${LLDB_PATH}/lib REQUIRED)
	target_link_libraries(debuggercore ${lib_lldb})
	target_include_directories(debuggercore PRIVATE ${LLDB_PATH}/include)
	set_property(TARGET debuggercore APPEND PROPERTY BUILD_RPATH "\$ORIGIN/lldb/lib")
	set(CMAKE_INSTALL_RPATH ${BN_CORE_PLUGIN_DIR}/lldb/lib)
	add_custom_command(TARGET debuggercore PRE_LINK
			COMMAND ${CMAKE_COMMAND} -E echo "Copying LLDB Libs"
			COMMAND ${CMAKE_COMMAND} -E make_directory ${BN_CORE_PLUGIN_DIR}/lldb/bin
			COMMAND ${CMAKE_COMMAND} -E make_directory ${BN_CORE_PLUGIN_DIR}/lldb/lib
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb ${BN_CORE_PLUGIN_DIR}/lldb/bin
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb-server ${BN_CORE_PLUGIN_DIR}/lldb/bin
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb-argdumper ${BN_CORE_PLUGIN_DIR}/lldb/bin
			# It is not perfect to hardcode the 14 here; but the debugger core links to it.
			# We should find a way to make the core link to liblldb.so instead.
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/lib/liblldb.so.14 ${BN_CORE_PLUGIN_DIR}/lldb/lib
			)
else()
	find_library(lib_lldb NAMES liblldb PATHS ${LLDB_PATH}/lib REQUIRED)
	target_link_libraries(debuggercore ${lib_lldb})
	target_include_directories(debuggercore PRIVATE ${LLDB_PATH}/include)
	add_custom_command(TARGET debuggercore PRE_LINK
			COMMAND ${CMAKE_COMMAND} -E echo "Copying LLDB Libs"
			COMMAND ${CMAKE_COMMAND} -E make_directory ${BN_CORE_PLUGIN_DIR}/lldb
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb.exe ${BN_CORE_PLUGIN_DIR}/lldb
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb-server.exe ${BN_CORE_PLUGIN_DIR}/lldb
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/lldb-argdumper.exe ${BN_CORE_PLUGIN_DIR}/lldb
			COMMAND ${CMAKE_COMMAND} -E copy ${LLDB_PATH}/bin/liblldb.dll ${BN_CORE_PLUGIN_DIR}
#			Since the UI links with the debugger core, BN fails to launch due to that the debuggercore is placed
#			in the plugins directory. A temporary workaround for this is to add the plugin path into the PATH
#			environment variable
#			COMMAND ${CMAKE_COMMAND} -E create_symlink ${BN_CORE_PLUGIN_DIR}/liblldb.dll ${BN_CORE_OUTPUT_DIR}
			)
endif()