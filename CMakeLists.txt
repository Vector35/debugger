cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(debugger)

if((NOT BN_API_PATH) AND (NOT BN_INTERNAL_BUILD))
	set(BN_API_PATH $ENV{BN_API_PATH})
	if(NOT BN_API_PATH)
		message(FATAL_ERROR "Provide path to Binary Ninja API source in BN_API_PATH")
	endif()
endif()

if (NOT BN_INTERNAL_BUILD)
	if(WIN32)
		set(MSVC_VERSION msvc2022_64 CACHE STRING "Version of MSVC Qt is built with" )
	endif()
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
		if(APPLE)
			set(CMAKE_PREFIX_PATH ${QT_INSTALL_DIR}/clang_64/lib/cmake)
		elseif(WIN32)
			set(CMAKE_PREFIX_PATH ${QT_INSTALL_DIR}/${MSVC_VERSION}/lib/cmake)
		else()
			set(CMAKE_PREFIX_PATH ${QT_INSTALL_DIR}/gcc_64/lib/cmake)
		endif()
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
