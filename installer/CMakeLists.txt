cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(windbg-installer)

# Only build on Windows
if(NOT WIN32)
    message(STATUS "WinDbg installer is Windows-only, skipping")
    return()
endif()

# ============================================================================
# minizip-ng library (minimal ZIP support)
# ============================================================================

set(MINIZIP_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/minizip-ng/mz_inflate.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/minizip-ng/mz_zip.cpp
)

set(MINIZIP_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/minizip-ng/mz.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/minizip-ng/mz_inflate.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/minizip-ng/mz_zip.h
)

add_library(minizip-ng STATIC ${MINIZIP_SOURCES} ${MINIZIP_HEADERS})

target_include_directories(minizip-ng PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/minizip-ng
)

# Prevent Windows min/max macros from conflicting with std::min/std::max
target_compile_definitions(minizip-ng PRIVATE NOMINMAX)

set_target_properties(minizip-ng PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)

# ============================================================================
# WinDbg installer library (used by standalone installer CLI)
# ============================================================================

set(INSTALLER_LIB_SOURCES
    http_downloader.cpp
    zip_extractor.cpp
    windbg_installer.cpp
)

set(INSTALLER_LIB_HEADERS
    http_downloader.h
    zip_extractor.h
    windbg_installer.h
)

# Add pugixml source
list(APPEND INSTALLER_LIB_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/pugixml/pugixml.cpp
)

add_library(windbg-installer-lib STATIC ${INSTALLER_LIB_SOURCES} ${INSTALLER_LIB_HEADERS})

target_include_directories(windbg-installer-lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/pugixml
    ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/minizip-ng
)

target_link_libraries(windbg-installer-lib
    PRIVATE minizip-ng
    PRIVATE winhttp.lib
    PRIVATE ole32.lib
    PRIVATE shell32.lib
)

set_target_properties(windbg-installer-lib PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)

# ============================================================================
# Standalone installer executable
# ============================================================================

add_executable(windbg-installer main.cpp)

target_link_libraries(windbg-installer
    PRIVATE windbg-installer-lib
)

set_target_properties(windbg-installer PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)

# Output to plugins directory (same as debuggercore)
if(BN_INTERNAL_BUILD)
    set_target_properties(windbg-installer PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
    )
else()
    set_target_properties(windbg-installer PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/plugins
    )
endif()

# Note: The installer is intentionally standalone and does not link with binaryninjaapi.
# Settings configuration is handled by the Binary Ninja UI after installation completes.
