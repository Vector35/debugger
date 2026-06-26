// A small executable that links against shared_lib and calls into it, so the dynamic loader maps
// the shared library at startup. The debugger tests analyze shared_lib but set the executable path
// to this program. See https://github.com/Vector35/debugger/issues/540.
#include <stdio.h>

#ifdef _WIN32
#define SHARED_LIB_IMPORT __declspec(dllimport)
#else
#define SHARED_LIB_IMPORT
#endif

SHARED_LIB_IMPORT int shared_lib_add(int a, int b);

int main()
{
	int result = shared_lib_add(40, 2);
	printf("result = %d\n", result);
	return 0;
}
