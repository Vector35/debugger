cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
project(x2winstub)

if(NOT WIN32)
    message(STATUS "x2winstub is Windows-only, skipping")
    return()
endif()

add_executable(x2winstub
    main.cpp
)

set_target_properties(x2winstub PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)


if(BN_INTERNAL_BUILD)
    set_target_properties(x2winstub PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
else()
    set_target_properties(x2winstub PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/plugins)
endif()

