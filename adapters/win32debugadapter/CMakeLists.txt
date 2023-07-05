project(win32debugadapter)

if(WIN32)
    file(GLOB SOURCES
            *.cpp
            *.h
            )

    if(DEMO)
        add_library(win32debugadapter STATIC ${SOURCES})
    else()
        add_library(win32debugadapter SHARED ${SOURCES})
    endif()

    target_link_libraries(win32debugadapter debuggerapi binaryninjaapi)

    if(BN_INTERNAL_BUILD)
        set(LIBRARY_OUTPUT_DIRECTORY_PATH "${BN_CORE_PLUGIN_DIR}")
    else()
        set(LIBRARY_OUTPUT_DIRECTORY_PATH "${CMAKE_BINARY_DIR}/out/plugins")
    endif()

    set_target_properties(win32debugadapter PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${LIBRARY_OUTPUT_DIRECTORY_PATH}
            RUNTIME_OUTPUT_DIRECTORY ${LIBRARY_OUTPUT_DIRECTORY_PATH}
            )

    set_target_properties(win32debugadapter PROPERTIES
            CXX_STANDARD 17
            CXX_VISIBILITY_PRESET hidden
            CXX_STANDARD_REQUIRED ON
            VISIBILITY_INLINES_HIDDEN ON
            POSITION_INDEPENDENT_CODE ON
            )
endif()
