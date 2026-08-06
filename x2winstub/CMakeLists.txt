cmake_minimum_required(VERSION 3.20)
project(x2winstub CXX)

if(NOT WIN32)
    message(STATUS "x2winstub is Windows-only, skipping")
    return()
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Only meaningful for MSVC-ABI-compatible compilers (cl/clang-cl); silently ignored otherwise, so
# guarding it isn't strictly required, but MinGW-w64 doesn't use /MT-style runtime selection at
# all and this being unconditional read as "x2winstub still needs MSVC" even after it no longer does.
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

add_executable(x2winstub
    main.cpp
    net/connection.cpp
    debug/windows_debug_engine.cpp
    x2win_session.cpp
)

# NOMINMAX: without it, <Windows.h> #defines max/min as function-like macros, which then mangle
# any std::numeric_limits<T>::max()/min() call textually (e.g. inside flatbuffers'
# flatbuffer_builder.h) into a syntax error -- this hit main.cpp/net/connection.cpp/x2win_session.cpp
# the moment they got rebuilt from a clean build directory (previously masked by incremental builds
# reusing stale, pre-existing .obj files instead of recompiling against the current headers).
# WIN32_LEAN_AND_MEAN trims <Windows.h> further (excludes rarely-needed APIs like GDI/Winsock v1);
# harmless here since net/connection.cpp already pulls in Winsock v2 explicitly.
target_compile_definitions(x2winstub PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)

target_include_directories(x2winstub PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# FlatBuffers replacement for the x2win RPC protocol (protocol/x2win.fbs). x2winstub actually ships
# and builds on its own (github.com/Vector35/X2WinStub), *not* nested under the main debugger
# monorepo -- the copy of this file (and this whole directory) inside the monorepo is a local
# mirror kept in sync by hand (see git log), not what runs the real build. So this can't assume a
# shared top-level CMakeLists.txt already vendored FlatBuffers for it the way core/CMakeLists.txt's
# debuggercore can: if x2win_fbs isn't already defined (i.e. we're building standalone, the way the
# real build does), vendor and generate it right here, exactly like the monorepo's top-level
# CMakeLists.txt does for core/ -- using this repo's own vendor/flatbuffers submodule. If it *is*
# already defined (this file was add_subdirectory()'d from that monorepo top-level after all),
# reuse that one instead of redefining the same target twice.
if(NOT TARGET x2win_fbs)
    set(FLATBUFFERS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(FLATBUFFERS_INSTALL OFF CACHE BOOL "" FORCE)
    set(FLATBUFFERS_BUILD_FLATC ON CACHE BOOL "" FORCE)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/vendor/flatbuffers ${CMAKE_CURRENT_BINARY_DIR}/vendor/flatbuffers)

    # Not using flatbuffers_generate_headers() here (unlike the monorepo's top-level CMakeLists.txt,
    # where the schema lives under the same directory the function is called from) -- its
    # source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} ...) call, meant purely for IDE file grouping,
    # hard-errors ("is not a prefix of file") because our schema is in a *sibling* directory
    # (../protocol/x2win.fbs), not underneath x2winstub/ itself. This is the same flatc invocation
    # that function does internally, just without that IDE-only step.
    set(X2WIN_FBS_SCHEMA ${CMAKE_CURRENT_SOURCE_DIR}/../protocol/x2win.fbs)
    set(X2WIN_FBS_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/x2win_fbs)
    set(X2WIN_FBS_GENERATED_HEADER ${X2WIN_FBS_GENERATED_DIR}/x2win_generated.h)
    add_custom_command(
        OUTPUT ${X2WIN_FBS_GENERATED_HEADER}
        COMMAND flatc -o ${X2WIN_FBS_GENERATED_DIR} -c ${X2WIN_FBS_SCHEMA}
        DEPENDS flatc ${X2WIN_FBS_SCHEMA}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Building ${X2WIN_FBS_SCHEMA} flatbuffers...")
    add_custom_target(GENERATE_x2win_fbs ALL DEPENDS ${X2WIN_FBS_GENERATED_HEADER})
    add_library(x2win_fbs INTERFACE)
    add_dependencies(x2win_fbs GENERATE_x2win_fbs)
    target_include_directories(x2win_fbs INTERFACE ${X2WIN_FBS_GENERATED_DIR})
endif()

# vendor/flatbuffers/include (CMAKE_SOURCE_DIR here resolves to whichever of the two vendor/
# copies above actually got used -- this repo's own when standalone, the monorepo's when nested,
# since CMAKE_SOURCE_DIR always means "root of the current build") is needed on top of the
# x2win_fbs link below because flatbuffers_generate_headers() only exposes the *generated*
# x2win_generated.h's directory via its INTERFACE target -- it doesn't add the FlatBuffers runtime
# headers (flatbuffers/flatbuffers.h etc.) that generated file itself #includes.
target_include_directories(x2winstub PRIVATE ${CMAKE_SOURCE_DIR}/vendor/flatbuffers/include)

# dbghelp is needed for WindowsDebugEngine::GetFramesOfThread's stack walking
# (SymInitialize/StackWalk64/etc.) -- the old debug_loop.cpp never did stack unwinding so never
# needed it. Linked normally here; WindowsNativeAdapter's original delay-load hook for dbghelp.dll
# (to avoid a version clash with the DbgEng adapter in the same *BN* process) doesn't apply to this
# standalone process, so that hook was dropped rather than ported -- see windows_debug_engine.cpp.
target_link_libraries(x2winstub PRIVATE x2win_fbs ws2_32 dbghelp)

if(BN_INTERNAL_BUILD)
    set_target_properties(x2winstub PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
else()
    set_target_properties(x2winstub PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/plugins)
endif()
