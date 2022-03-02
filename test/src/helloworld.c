// tests: cmdline arguments, process return value, stdout

#include <stdio.h>

int main(int argc, char **argv)
{
	int i;

	printf("Hello, world!\n");

	printf("argc: %d\n", argc);
	for(i=0; i<argc; ++i)
		printf("argv[%d]: %s\n", i, argv[i]);

	return 10;
}
