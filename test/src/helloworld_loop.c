#include <stdio.h>

#if defined(_WIN32) || defined(_WIN64)
#include <process.h>
#define PIDFUNC _getpid
#else
#include <unistd.h>
#define PIDFUNC getpid
#endif

int main(int ac, char **av)
{
	int i;
	for(i=0; 1; i++) {
		int process_id = PIDFUNC();

		printf("Hello, world! pid:%d i:%d\n", process_id, i);
		int j;
		for(j=0; j<100000000; ++j)
			i = i*7;
	}
	return 11;
}
