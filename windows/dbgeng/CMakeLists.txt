add_library(dbgengengine INTERFACE)
target_sources(dbgengengine INTERFACE
	${CMAKE_CURRENT_SOURCE_DIR}/dbgengtypes.h
	${CMAKE_CURRENT_SOURCE_DIR}/dbgenglog.h
	${CMAKE_CURRENT_SOURCE_DIR}/dbgenglog.cpp)
target_include_directories(dbgengengine INTERFACE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/core)

add_library(dbgengengine_check OBJECT)
target_link_libraries(dbgengengine_check PRIVATE dbgengengine)
set_property(TARGET dbgengengine_check PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
