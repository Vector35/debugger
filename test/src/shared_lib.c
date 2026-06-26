// A minimal shared library used by the debugger unit tests. It is analyzed as the input file
// while the executable path is pointed at load_shared_lib (the program that loads it). This
// reproduces the scenario from https://github.com/Vector35/debugger/issues/540 and the bug in
// https://github.com/Vector35/debugger/issues/1104 where the debugger tried to exec the library
// directly instead of the executable that loads it.
#include <stdio.h>

#ifdef _WIN32
#define SHARED_LIB_EXPORT __declspec(dllexport)
#else
#define SHARED_LIB_EXPORT __attribute__((visibility("default")))
#endif

SHARED_LIB_EXPORT int shared_lib_add(int a, int b)
{
	int result = a + b;
	printf("shared_lib_add(%d, %d) = %d\n", a, b, result);
	return result;
}
