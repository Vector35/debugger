add_library(dbgengengine INTERFACE)
target_sources(dbgengengine INTERFACE
	${CMAKE_CURRENT_SOURCE_DIR}/dbgengtypes.h
	${CMAKE_CURRENT_SOURCE_DIR}/dbgenglog.h
	${CMAKE_CURRENT_SOURCE_DIR}/dbgenglog.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/dbgengengine.h
	${CMAKE_CURRENT_SOURCE_DIR}/dbgengengine.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/dbgengttdengine.h
	${CMAKE_CURRENT_SOURCE_DIR}/dbgengttdengine.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/dbgengdumpengine.h
	${CMAKE_CURRENT_SOURCE_DIR}/dbgengdumpengine.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/dbgengkernelengine.h
	${CMAKE_CURRENT_SOURCE_DIR}/dbgengkernelengine.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/dbgenglocalkernelengine.h
	${CMAKE_CURRENT_SOURCE_DIR}/dbgenglocalkernelengine.cpp)
target_include_directories(dbgengengine INTERFACE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/core)

add_library(dbgengengine_check OBJECT)
target_link_libraries(dbgengengine_check PRIVATE dbgengengine)
set_property(TARGET dbgengengine_check PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
