cmake_minimum_required(VERSION 3.28 FATAL_ERROR)

project(dbgengengine)

add_library(dbgengengine STATIC
	dbgengtypes.h
	dbgenglog.cpp
	dbgenglog.h
	dbgengengine.cpp
	dbgengengine.h
	dbgengttdengine.cpp
	dbgengttdengine.h
	dbgengdumpengine.cpp
	dbgengdumpengine.h
	dbgengkernelengine.cpp
	dbgengkernelengine.h
	dbgenglocalkernelengine.cpp
	dbgenglocalkernelengine.h
)
