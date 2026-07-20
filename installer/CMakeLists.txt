cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(windbg-installer)

# Only build on Windows
if(NOT WIN32)
    message(STATUS "WinDbg installer is Windows-only, skipping")
    return()
endif()

# ============================================================================
# miniz library (ZIP + inflate) - vendored amalgamation
# ============================================================================

add_library(miniz STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/miniz/miniz.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/miniz/miniz.h
)

target_include_directories(miniz PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/miniz
)

# miniz uses fopen etc.; silence MSVC CRT deprecation warnings
target_compile_definitions(miniz PRIVATE _CRT_SECURE_NO_WARNINGS)

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
    ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/miniz
)

target_link_libraries(windbg-installer-lib
    PRIVATE miniz
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
