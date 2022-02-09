cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(debuggerui)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

file(GLOB SOURCES *.cpp *.h)
list(FILTER SOURCES EXCLUDE REGEX moc_.*)
list(FILTER SOURCES EXCLUDE REGEX qrc_.*)

if(DEMO)
    add_library(debuggerui STATIC ${SOURCES})
else()
    add_library(debuggerui SHARED ${SOURCES})
endif()

#if(DEMO)
#    target_compile_definitions(binaryninja PRIVATE DEMO_VERSION)
#    target_link_libraries(binaryninja triage
#            arch_armv7 arch_arm64 arch_mips arch_ppc arch_x86
#            platform_decree platform_freebsd platform_linux platform_mac platform_windows)
#elseif(ENTERPRISE)
#    target_compile_definitions(binaryninja PRIVATE ENTERPRISE_VERSION)
#elseif(PERSONAL)
#    target_compile_definitions(binaryninja PRIVATE PERSONAL_VERSION)
#endif()
#
#if(CMAKE_BUILD_TYPE MATCHES Debug OR CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)
#    target_compile_definitions(binaryninja PRIVATE _DEBUG)
#else()
#    target_compile_definitions(binaryninja PRIVATE NDEBUG)
#endif()

#set_target_properties(debuggerui PROPERTIES
#        CXX_STANDARD 17
#        CXX_STANDARD_REQUIRED ON
#        CXX_VISIBILITY_PRESET hidden
#        VISIBILITY_INLINES_HIDDEN ON
#        POSITION_INDEPENDENT_CODE ON
#        )


set_target_properties(debuggerui PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
        LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
        RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
        )

#if(APPLE)
#    set_target_properties(binaryninja PROPERTIES
#            INSTALL_RPATH "@loader_path;@loader_path/../Frameworks")
#elseif(UNIX)
#    set_target_properties(binaryninja PROPERTIES
#            BUILD_WITH_INSTALL_RPATH OFF)
#    target_link_libraries(binaryninja dl)
#elseif(WIN32)
#    set_target_properties(binaryninja PROPERTIES
#            LINK_FLAGS /SUBSYSTEM:WINDOWS)
#    if(QT6)
#        target_link_libraries(binaryninja Qt6::EntryPoint)
#    else()
#        target_link_libraries(binaryninja Qt5::WinMain)
#    endif()
#    target_link_libraries(binaryninja "${CMAKE_CURRENT_SOURCE_DIR}/../resource/appicon.res")
#endif()

target_link_libraries(debuggerui debuggerapi binaryninjaui binaryninjaapi Qt6::Core Qt6::Gui Qt6::Widgets)

include_directories(../vendor)
