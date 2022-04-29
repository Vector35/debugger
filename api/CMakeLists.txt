cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(debuggerapi)

file(GLOB BN_DEBUGGER_API_SOURCES *.cpp *.h)
add_library(debuggerapi STATIC ${BN_DEBUGGER_API_SOURCES})

target_include_directories(debuggerapi
        PUBLIC ${PROJECT_SOURCE_DIR})

target_link_libraries(debuggerapi PUBLIC debuggercore)

#if((NOT BN_CORE_LIBRARY) AND (NOT BN_INTERNAL_BUILD))
#    find_library(BN_DEBUGGER_CORE_LIBRARY REQUIRED
#            NAMES debuggercore libdebuggercore.so.1
#            PATHS ${BN_INSTALL_BIN_DIR})
#
#    if(BN_DEBUGGER_CORE_LIBRARY)
#        message(STATUS "Debugger Core: ${BN_DEBUGGER_CORE_LIBRARY}")
#    else()
#        message(FATAL_ERROR "Debugger Core Not Found")
#    endif()
#endif()
#
#if(NOT HEADLESS)
#    if((NOT BN_UI_LIBRARY) AND (NOT BN_INTERNAL_BUILD))
#        find_library(BN_UI_LIBRARY REQUIRED
#                NAMES binaryninjaui libbinaryninjaui.so.1
#                PATHS ${BN_INSTALL_BIN_DIR})
#
#        if(BN_UI_LIBRARY)
#            message(STATUS "Binary Ninja UI: ${BN_UI_LIBRARY}")
#        else()
#            message(FATAL_ERROR "Binary Ninja UI Not Found")
#        endif()
#    endif()
#endif()
#
#if(NOT BN_INTERNAL_BUILD)
#    target_link_libraries(binaryninjaapi PUBLIC ${BN_CORE_LIBRARY})
#    target_link_directories(binaryninjaapi PUBLIC ${BN_INSTALL_BIN_DIR})
#else()
#    target_link_libraries(debuggerapi PUBLIC debuggercore)
#endif()
#
#if(NOT HEADLESS)
#    target_include_directories(binaryninjaapi PUBLIC ${PROJECT_SOURCE_DIR}/ui)
#
#    if(NOT BN_INTERNAL_BUILD)
#        target_link_libraries(binaryninjaapi PUBLIC ${BN_UI_LIBRARY})
#        target_link_directories(binaryninjaapi PUBLIC ${BN_INSTALL_BIN_DIR})
#    else()
#        # Nothing
#    endif()
#endif()

set_target_properties(debuggerapi PROPERTIES
        CXX_STANDARD 17
        CXX_VISIBILITY_PRESET hidden
        CXX_STANDARD_REQUIRED ON
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/out)

include_directories(../vendor)

if (NOT DEMO)
    add_subdirectory(python)
endif()